"""Candidate-bound repository allocation core and finite controller.

One fixed GitHub ledger is the authority for cooperating Desktop/CLI/CI clients.
Conditional contents writes serialize its append; max+1 and a local mutex do
NOT provide distributed allocation. The protected branch must prohibit deletion
and force updates. Blob CAS is not branch-head CAS, and a fresh client with only
genesis cannot detect a privileged administrator's valid-looking rollback.

There is deliberately NO live transport factory, credential access, local-file
allocator, implicit genesis creation, automatic retry or public command route.
The original application owner supplies authenticated transport, durable journal,
clock, project exclusion and scoped consent. DTOs and successful readback do not
establish those owners' finality, artifact provenance or Store eligibility.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any, Callable, Protocol
from uuid import UUID

from . import version_policy as policy
from ._desktop_github_engine import _check_control, _decode_json
from ._github_connection_transport import ReadFailure, ReadResult, _control
from .api._github_connection import _coordinate, _id, _repository
from .api._json import bounded_json_text
from .config import ReleaseVersion
from .github_preflight import HttpRequest

PROTOCOL = "mrk-version-allocation/1"
LEDGER_BRANCH = "mrk-version-allocations"
LEDGER_PATH = "release/.mrk-version-allocations-v1.json"
MAX_RESERVATIONS = 64
MAX_LEDGER_BYTES = 128 * 1024
MAX_PENDING_BYTES = 16 * 1024
MAX_HTTP_BYTES = 256 * 1024
MAX_REQUESTS = 10
REASONS = policy.REASONS | frozenset({"none", "authority-unavailable", "authority-untrusted",
    "authority-changed", "authority-missing", "authority-rewound", "ledger-invalid", "ledger-full",
    "candidate-binding-conflict", "conditional-conflict", "pending-unresolved", "journal-unavailable",
    "source-changed", "invalid-allocation", "unauthorized", "forbidden", "rate-limited",
    "target-changed", "not-found-or-inaccessible",
    "network-unavailable", "tls-failed", "response-invalid", "response-limit", "expired", "cancelled"})


class VersionAllocationError(ValueError):
    def __init__(self, reason: str = "invalid-allocation") -> None:
        self.reason = reason if reason in REASONS else "invalid-allocation"
        super().__init__("Version allocation was refused")


def _need(condition: bool, reason: str = "invalid-allocation") -> None:
    if not condition:
        raise VersionAllocationError(reason)


def _uuid(value: object) -> str:
    _need(type(value) is str and len(value) == 36)
    try:
        parsed = UUID(value)
        _need(parsed.version == 4 and str(parsed) == value)
    except (ValueError, AttributeError):
        raise VersionAllocationError() from None
    return value


def _project_id(value: object) -> str:
    # Native shared-service IDs are nonzero lowerhex32, not a UUID claim.
    # Legacy release enrollment UUIDs remain distinct exact strings. Never
    # normalize either form, even if stripping hyphens yields the same bytes.
    if (type(value) is str and len(value) == 32 and value != "0" * 32
            and all(char in "0123456789abcdef" for char in value)):
        return value
    return _uuid(value)


def _hash(domain: bytes, value: object) -> str:
    return hashlib.sha256(domain + policy.canonical(value)).hexdigest()


def blob_sha(raw: bytes) -> str:
    """The supported authority is a SHA-1 Git repository, not an arbitrary URL."""
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_LEDGER_BYTES)
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


@dataclass(frozen=True, slots=True)
class AllocationRequest:
    project_id: str
    candidate_id: str
    identity_revision: str
    source: policy.SourceBinding
    base_version: ReleaseVersion
    enabled_platforms: tuple[str, ...]
    version_policy: policy.VersionPolicy = policy.VersionPolicy()

    def __post_init__(self) -> None:
        _project_id(self.project_id)
        _uuid(self.candidate_id)
        policy._match(self.identity_revision, policy._DIGEST)
        _need(type(self.source) is policy.SourceBinding and type(self.version_policy) is policy.VersionPolicy)
        policy.version(self.base_version, self.enabled_platforms)

    @classmethod
    def parse(cls, value: object) -> AllocationRequest:
        row = policy._object(value, {"projectId", "candidateId", "identityRevision", "source",
                                     "baseVersion", "platforms", "policy"})
        _need(type(row["platforms"]) is list and len(row["platforms"]) <= 2)
        enabled = policy.platforms(tuple(row["platforms"]))
        return cls(row["projectId"], row["candidateId"], row["identityRevision"],
                   policy.SourceBinding.parse(row["source"]), policy.parse_version(row["baseVersion"], enabled),
                   enabled, policy.VersionPolicy.parse(row["policy"]))

    def value(self) -> dict[str, Any]:
        return {"projectId": self.project_id, "candidateId": self.candidate_id,
                "identityRevision": self.identity_revision, "source": self.source.value(),
                "baseVersion": policy.version_value(self.base_version), "platforms": list(self.enabled_platforms),
                "policy": self.version_policy.value()}

    @property
    def sha256(self) -> str:
        return _hash(b"mrk:allocation-request:1\0", self.value())


@dataclass(frozen=True, slots=True)
class Genesis:
    """Explicit setup DATA. An absent remote ledger NEVER creates this implicitly."""
    project_id: str
    repository_id: str
    ledger_id: str
    initial_version: ReleaseVersion

    def __post_init__(self) -> None:
        _project_id(self.project_id)
        _id(self.repository_id)
        _uuid(self.ledger_id)
        policy.version(self.initial_version, ("android",), automatic=True)

    @classmethod
    def parse(cls, value: object) -> Genesis:
        row = policy._object(value, {"projectId", "repositoryId", "ledgerId", "initialVersion", "branch", "path"})
        _need(row["branch"] == LEDGER_BRANCH and row["path"] == LEDGER_PATH, "ledger-invalid")
        return cls(row["projectId"], row["repositoryId"], row["ledgerId"],
                   policy.parse_version(row["initialVersion"], ("android",), automatic=True))

    def value(self) -> dict[str, Any]:
        return {"projectId": self.project_id, "repositoryId": self.repository_id, "ledgerId": self.ledger_id,
                "initialVersion": policy.version_value(self.initial_version),
                "branch": LEDGER_BRANCH, "path": LEDGER_PATH}

    @property
    def sha256(self) -> str:
        return _hash(b"mrk:allocation-genesis:1\0", self.value())


@dataclass(frozen=True, slots=True)
class AuthorityRegistration:
    project_id: str
    repository: str
    repository_id: str
    ledger_id: str
    genesis_sha256: str
    protected_branch: bool

    def __post_init__(self) -> None:
        _project_id(self.project_id)
        _coordinate(self.repository)
        _id(self.repository_id)
        _uuid(self.ledger_id)
        policy._match(self.genesis_sha256, policy._DIGEST)
        _need(type(self.protected_branch) is bool)

    @classmethod
    def parse(cls, value: object) -> AuthorityRegistration:
        row = policy._object(value, {"projectId", "repository", "repositoryId", "ledgerId",
                                     "genesisSha256", "protectedBranch"})
        return cls(row["projectId"], row["repository"], row["repositoryId"], row["ledgerId"],
                   row["genesisSha256"], row["protectedBranch"])

    def value(self) -> dict[str, Any]:
        return {"projectId": self.project_id, "repository": self.repository, "repositoryId": self.repository_id,
                "ledgerId": self.ledger_id, "genesisSha256": self.genesis_sha256,
                "protectedBranch": self.protected_branch}


@dataclass(frozen=True, slots=True)
class Checkpoint:
    sequence: int
    head_sha256: str
    commit: str

    def __post_init__(self) -> None:
        policy._integer(self.sequence, MAX_RESERVATIONS)
        policy._match(self.head_sha256, policy._DIGEST)
        policy._match(self.commit, policy._SHA)

    @classmethod
    def parse(cls, value: object) -> Checkpoint:
        row = policy._object(value, {"sequence", "headSha256", "commit"})
        return cls(row["sequence"], row["headSha256"], row["commit"])

    def value(self) -> dict[str, Any]:
        return {"sequence": self.sequence, "headSha256": self.head_sha256, "commit": self.commit}


@dataclass(frozen=True, slots=True)
class Reservation:
    sequence: int
    previous_sha256: str
    request: AllocationRequest
    version: ReleaseVersion
    store_observations: tuple[policy.StoreObservation, ...]
    allocated_at: int

    def __post_init__(self) -> None:
        policy._integer(self.sequence, MAX_RESERVATIONS, 1)
        policy._match(self.previous_sha256, policy._DIGEST)
        _need(type(self.request) is AllocationRequest and self.request.version_policy.mode == "automatic")
        policy.version(self.version, self.request.enabled_platforms, automatic=True)
        _need(type(self.store_observations) is tuple and len(self.store_observations) <= 2
              and all(type(item) is policy.StoreObservation for item in self.store_observations))
        policy._integer(self.allocated_at, (1 << 63) - 1)

    @classmethod
    def parse(cls, value: object) -> Reservation:
        row = policy._object(value, {"sequence", "previousSha256", "request", "requestSha256",
                                     "version", "storeObservations", "allocatedAt", "sha256"})
        request = AllocationRequest.parse(row["request"])
        _need(type(row["storeObservations"]) is list and len(row["storeObservations"]) <= 2)
        result = cls(row["sequence"], row["previousSha256"], request,
                     policy.parse_version(row["version"], request.enabled_platforms, automatic=True),
                     tuple(policy.StoreObservation.parse(item) for item in row["storeObservations"]), row["allocatedAt"])
        _need(result.request.sha256 == row["requestSha256"] and result.sha256 == row["sha256"], "ledger-invalid")
        return result

    def _value(self) -> dict[str, Any]:
        return {"sequence": self.sequence, "previousSha256": self.previous_sha256,
                "request": self.request.value(), "requestSha256": self.request.sha256,
                "version": policy.version_value(self.version),
                "storeObservations": [item.value() for item in self.store_observations], "allocatedAt": self.allocated_at}

    @property
    def sha256(self) -> str:
        return _hash(b"mrk:allocation-reservation:1\0", self._value())

    def value(self) -> dict[str, Any]:
        return {**self._value(), "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class Ledger:
    genesis: Genesis
    reservations: tuple[Reservation, ...] = ()

    def __post_init__(self) -> None:
        _need(type(self.genesis) is Genesis and type(self.reservations) is tuple
              and len(self.reservations) <= MAX_RESERVATIONS, "ledger-invalid")
        previous, allocated, candidates = self.genesis.sha256, self.genesis.initial_version, set()
        for sequence, item in enumerate(self.reservations, 1):
            _need(type(item) is Reservation and item.sequence == sequence and item.previous_sha256 == previous
                  and item.request.project_id == self.genesis.project_id
                  and item.request.candidate_id not in candidates, "ledger-invalid")
            expected = _propose(item.request, allocated, item.store_observations, item.allocated_at)
            _need(item.version == expected and item.version.build > allocated.build, "ledger-invalid")
            candidates.add(item.request.candidate_id)
            previous, allocated = item.sha256, item.version

    @property
    def head_sha256(self) -> str:
        return self.reservations[-1].sha256 if self.reservations else self.genesis.sha256

    @property
    def last_version(self) -> ReleaseVersion:
        return self.reservations[-1].version if self.reservations else self.genesis.initial_version

    def value(self) -> dict[str, Any]:
        return {"schemaVersion": 1, "protocol": PROTOCOL, "genesis": self.genesis.value(),
                "reservations": [item.value() for item in self.reservations]}

    def to_bytes(self) -> bytes:
        raw = policy.canonical(self.value()) + b"\n"
        _need(len(raw) <= MAX_LEDGER_BYTES, "ledger-full")
        return raw

    @classmethod
    def parse(cls, raw: bytes, authority: AuthorityRegistration) -> Ledger:
        try:
            _need(type(raw) is bytes and 0 < len(raw) <= MAX_LEDGER_BYTES
                  and raw.endswith(b"\n") and raw.count(b"\n") == 1, "ledger-invalid")
            row = policy._object(_decode_json(raw[:-1], limit=MAX_LEDGER_BYTES - 1, nodes=20_000, depth=16, exact=True),
                                 {"schemaVersion", "protocol", "genesis", "reservations"})
            _need(type(row["schemaVersion"]) is int and row["schemaVersion"] == 1 and row["protocol"] == PROTOCOL
                  and type(row["reservations"]) is list and len(row["reservations"]) <= MAX_RESERVATIONS, "ledger-invalid")
            result = cls(Genesis.parse(row["genesis"]), tuple(Reservation.parse(item) for item in row["reservations"]))
            result.admit(authority)
            _need(result.to_bytes() == raw, "ledger-invalid")
            return result
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise VersionAllocationError("ledger-invalid") from None

    def admit(self, authority: AuthorityRegistration, checkpoint: Checkpoint | None = None) -> None:
        _need(type(authority) is AuthorityRegistration and self.genesis.project_id == authority.project_id
              and self.genesis.repository_id == authority.repository_id and self.genesis.ledger_id == authority.ledger_id
              and self.genesis.sha256 == authority.genesis_sha256, "authority-changed")
        if checkpoint is not None:
            _need(type(checkpoint) is Checkpoint and checkpoint.sequence <= len(self.reservations), "authority-rewound")
            retained = self.genesis.sha256 if checkpoint.sequence == 0 else self.reservations[checkpoint.sequence - 1].sha256
            _need(retained == checkpoint.head_sha256, "authority-rewound")

    def find(self, request: AllocationRequest) -> Reservation | None:
        for item in self.reservations:
            if item.request.candidate_id == request.candidate_id:
                _need(item.request == request, "candidate-binding-conflict")
                return item
        return None

    def append(self, request: AllocationRequest, observations: tuple[policy.StoreObservation, ...], *, now: int) -> Ledger:
        _need(request.project_id == self.genesis.project_id, "authority-changed")
        _need(self.find(request) is None, "candidate-binding-conflict")
        _need(len(self.reservations) < MAX_RESERVATIONS, "ledger-full")
        item = Reservation(len(self.reservations) + 1, self.head_sha256, request,
                           _propose(request, self.last_version, observations, now), observations, now)
        result = Ledger(self.genesis, (*self.reservations, item))
        result.to_bytes()
        return result


def _propose(request: AllocationRequest, allocated: ReleaseVersion,
             observations: tuple[policy.StoreObservation, ...], now: int) -> ReleaseVersion:
    return policy.propose_version(request.version_policy, source=request.source.ref, base=request.base_version,
        allocated=allocated, enabled=request.enabled_platforms, identity_revision=request.identity_revision,
        observations=observations, now=now)


@dataclass(frozen=True, slots=True)
class LedgerSnapshot:
    ledger: Ledger
    commit: str
    blob: str

    def __post_init__(self) -> None:
        _need(type(self.ledger) is Ledger)
        policy._match(self.commit, policy._SHA)
        _need(self.blob == blob_sha(self.ledger.to_bytes()), "ledger-invalid")

    @property
    def checkpoint(self) -> Checkpoint:
        return Checkpoint(len(self.ledger.reservations), self.ledger.head_sha256, self.commit)


@dataclass(frozen=True, slots=True)
class PendingAllocation:
    """Durable pre-send intent. Reloading this grants READ-ONLY reconciliation."""
    authority: AuthorityRegistration
    checkpoint: Checkpoint
    expected_blob: str
    reservation: Reservation

    def __post_init__(self) -> None:
        _need(type(self.authority) is AuthorityRegistration and type(self.checkpoint) is Checkpoint
              and type(self.reservation) is Reservation
              and self.reservation.request.project_id == self.authority.project_id
              and self.reservation.sequence == self.checkpoint.sequence + 1
              and self.reservation.previous_sha256 == self.checkpoint.head_sha256)
        policy._match(self.expected_blob, policy._SHA)

    def value(self) -> dict[str, Any]:
        return {"schemaVersion": 1, "protocol": PROTOCOL, "authority": self.authority.value(),
                "checkpoint": self.checkpoint.value(), "expectedBlob": self.expected_blob,
                "reservation": self.reservation.value()}

    def to_bytes(self) -> bytes:
        raw = policy.canonical(self.value()) + b"\n"
        _need(len(raw) <= MAX_PENDING_BYTES)
        return raw

    @classmethod
    def parse(cls, raw: bytes) -> PendingAllocation:
        _need(type(raw) is bytes and 0 < len(raw) <= MAX_PENDING_BYTES
              and raw.endswith(b"\n") and raw.count(b"\n") == 1)
        row = policy._object(_decode_json(raw[:-1], limit=MAX_PENDING_BYTES - 1, nodes=1024, depth=16, exact=True),
            {"schemaVersion", "protocol", "authority", "checkpoint", "expectedBlob", "reservation"})
        _need(type(row["schemaVersion"]) is int and row["schemaVersion"] == 1 and row["protocol"] == PROTOCOL)
        result = cls(AuthorityRegistration.parse(row["authority"]), Checkpoint.parse(row["checkpoint"]),
                     row["expectedBlob"], Reservation.parse(row["reservation"]))
        _need(result.to_bytes() == raw)
        return result


class AllocationJournal(Protocol):
    """Original owner adapter, not a replaceable local allocation authority.

    Each write returns only AFTER durable settlement. Checkpoints never regress.
    Pending intents survive errors/restart; only this exact controller's positive
    rejection or matching remote reservation can settle them. The application
    must serialize admission/updates for a project across its local clients.
    """
    def checkpoint(self, authority: AuthorityRegistration) -> Checkpoint: ...
    def pending_for(self, authority: AuthorityRegistration, candidate_id: str) -> PendingAllocation | None: ...
    def record_checkpoint(self, authority: AuthorityRegistration, checkpoint: Checkpoint) -> None: ...
    def record_pending(self, pending: PendingAllocation) -> None: ...
    def mark_resolved(self, pending: PendingAllocation, checkpoint: Checkpoint) -> None: ...
    def mark_rejected(self, pending: PendingAllocation) -> None: ...


class AllocationTransport(Protocol):
    """Closed-role adapter to the EXISTING original GitHub HTTP owner.

    Native account/CI identity admission, authorization, TLS, byte/deadline
    budgets, cooldown and finality stay there. There is no live adapter here;
    ordinary existing transport roles do not authorize these new endpoints.
    """
    def exchange(self, step: str, request: HttpRequest) -> ReadResult: ...


def conditional_write_body(pending: PendingAllocation, after: Ledger) -> bytes:
    _need(type(pending) is PendingAllocation and type(after) is Ledger and bool(after.reservations))
    after.admit(pending.authority, pending.checkpoint)
    _need(after.reservations[-1] == pending.reservation)
    before = Ledger(after.genesis, after.reservations[:-1])
    _need(blob_sha(before.to_bytes()) == pending.expected_blob)
    raw = policy.canonical({"message": "Reserve Mobile Release Kit candidate version", "branch": LEDGER_BRANCH,
                            "sha": pending.expected_blob, "content": base64.b64encode(after.to_bytes()).decode("ascii")})
    _need(len(raw) <= MAX_HTTP_BYTES)
    return raw


class Schedule:
    """One finite read/conditional-write schedule; no user-selected endpoint."""
    def __init__(self, authority: AuthorityRegistration, checkpoint: Checkpoint, *, reconcile: bool = False) -> None:
        _need(type(authority) is AuthorityRegistration and type(checkpoint) is Checkpoint and type(reconcile) is bool)
        self.authority, self.checkpoint, self.reconcile = authority, checkpoint, reconcile
        self.steps: list[str] = []
        self.before_commit: str | None = None
        self.after_commit: str | None = None

    def claim(self, step: str, reference: str | None = None, *, body: bytes | None = None) -> HttpRequest:
        prefix = ("repository-before", "ref-before", "compare-before", "ledger-before")
        if len(self.steps) < len(prefix):
            allowed = {prefix[len(self.steps)]}
        else:
            allowed = {"ledger-before": {"repository-after"} if self.reconcile else {"write", "repository-after"},
                       "write": {"ref-after"}, "ref-after": {"compare-after"},
                       "compare-after": {"ledger-after"}, "ledger-after": {"repository-after"}}.get(self.steps[-1], set())
        _need(step in allowed and len(self.steps) < MAX_REQUESTS)
        root = "/repos/" + self.authority.repository
        if step in {"repository-before", "repository-after"}:
            path = root
        elif step in {"ref-before", "ref-after"}:
            path = root + "/git/ref/heads/" + LEDGER_BRANCH
        elif step in {"compare-before", "compare-after"}:
            commit = policy._match(reference, policy._SHA)
            old = self.checkpoint.commit if step == "compare-before" else self.before_commit
            _need(old is not None)
            if step == "compare-before":
                self.before_commit = commit
            else:
                self.after_commit = commit
            path = root + "/compare/" + old + "..." + commit + "?per_page=1&page=1"
        elif step in {"ledger-before", "ledger-after"}:
            commit = self.before_commit if step == "ledger-before" else self.after_commit
            _need(commit is not None and reference == commit)
            path = root + "/contents/" + LEDGER_PATH + "?ref=" + commit
        else:
            _need(step == "write" and not self.reconcile and type(body) is bytes and 0 < len(body) <= MAX_HTTP_BYTES)
            path = root + "/contents/" + LEDGER_PATH
        _need((reference is None) == (step not in {"compare-before", "compare-after", "ledger-before", "ledger-after"})
              and (body is None) == (step != "write"))
        self.steps.append(step)  # Claimed even if exchange later fails/never sends.
        return HttpRequest("PUT" if step == "write" else "GET", path, body)


@dataclass(frozen=True, slots=True)
class AllocationOutcome:
    status: str
    reason: str
    reservation: Reservation | None = None
    checkpoint: Checkpoint | None = None
    write_claimed: bool = False
    write_acknowledged: bool = False
    control: dict[str, Any] | None = None

    def value(self) -> dict[str, Any]:
        return {"schemaVersion": 1, "status": self.status, "reason": self.reason,
                "reservation": None if self.reservation is None else self.reservation.value(),
                "checkpoint": None if self.checkpoint is None else self.checkpoint.value(),
                "writeClaimed": self.write_claimed, "writeAcknowledged": self.write_acknowledged,
                "control": dict(self.control or _control()), "releaseEligibility": "not-established",
                "assurance": "repository-allocation-data-not-native-finality"}


def _repository_identity(body: dict[str, Any], authority: AuthorityRegistration) -> None:
    selected = _repository(body)
    _need(selected["id"] == authority.repository_id
          and selected["fullName"].lower() == authority.repository.lower(), "authority-changed")
    _need(not selected["archived"], "authority-unavailable")


def _ref_commit(body: dict[str, Any]) -> str:
    _need(body.get("ref") == "refs/heads/" + LEDGER_BRANCH and type(body.get("object")) is dict
          and body["object"].get("type") == "commit", "authority-changed")
    return policy._match(body["object"].get("sha"), policy._SHA)


def _ancestry(body: dict[str, Any], expected: str, current: str) -> None:
    _need(body.get("status") == ("identical" if expected == current else "ahead")
          and type(body.get("base_commit")) is dict and type(body.get("merge_base_commit")) is dict
          and body["base_commit"].get("sha") == expected and body["merge_base_commit"].get("sha") == expected,
          "authority-rewound")


def _snapshot(body: dict[str, Any], commit: str, authority: AuthorityRegistration, checkpoint: Checkpoint) -> LedgerSnapshot:
    _need(body.get("type") == "file" and body.get("path") == LEDGER_PATH
          and body.get("encoding") == "base64" and "target" not in body and "submodule_git_url" not in body,
          "ledger-invalid")
    size = policy._integer(body.get("size"), MAX_LEDGER_BYTES, 1)
    encoded = body.get("content")
    _need(type(encoded) is str and len(encoded) <= 2 * MAX_LEDGER_BYTES, "ledger-invalid")
    try:
        raw = base64.b64decode(encoded.replace("\n", ""), validate=True)
    except ValueError:
        raise VersionAllocationError("ledger-invalid") from None
    _need(len(raw) == size and blob_sha(raw) == body.get("sha"), "ledger-invalid")
    ledger = Ledger.parse(raw, authority)
    ledger.admit(authority, checkpoint)
    return LedgerSnapshot(ledger, commit, body["sha"])


def allocate_version(request: AllocationRequest, authority: AuthorityRegistration | None,
                     transport: AllocationTransport | None, journal: AllocationJournal, *,
                     observations: tuple[policy.StoreObservation, ...], clock: Callable[[], int]) -> AllocationOutcome:
    """Explicit reserve action. Original native finality remains the caller's job.

    After restart an unresolved durable intent forces read-only reconciliation.
    A missing reservation is not evidence of no send. Definite CAS conflicts may
    be refreshed by a NEW explicit action; this controller never loops/retries.
    Reused reservations are allocated DATA, including when Store checks are now
    stale/consumed. Use check_reserved_for_new_release in the existing release
    admission, or the original release recovery owner, before any new upload.
    """
    _need(type(request) is AllocationRequest)
    if request.version_policy.mode == "manual":
        return AllocationOutcome("manual", "manual-policy")
    pending: PendingAllocation | None = None
    write_claimed = acknowledged = False
    control = _control()
    checkpoint: Checkpoint | None = None

    def outcome(status: str, reason: str, reservation: Reservation | None = None) -> AllocationOutcome:
        return AllocationOutcome(status, reason, reservation, checkpoint, write_claimed, acknowledged, dict(control))

    def persist(method: Callable[..., Any], *args: object) -> Any:
        try:
            return method(*args)
        except Exception:
            raise VersionAllocationError("journal-unavailable") from None

    try:
        request.version_policy.increment_for(request.source.ref)
        _need(type(authority) is AuthorityRegistration, "authority-unavailable")
        _need(authority.protected_branch, "authority-untrusted")
        _need(authority.project_id == request.project_id, "authority-changed")
        checkpoint = persist(journal.checkpoint, authority)
        _need(type(checkpoint) is Checkpoint, "journal-unavailable")
        pending = persist(journal.pending_for, authority, request.candidate_id)
        if pending is not None:
            _need(type(pending) is PendingAllocation and pending.authority == authority, "journal-unavailable")
            _need(pending.reservation.request == request, "candidate-binding-conflict")
        _need(transport is not None, "authority-unavailable")
        schedule = Schedule(authority, checkpoint, reconcile=pending is not None)

        def take(step: str, reference: str | None = None, *, body: bytes | None = None) -> tuple[int, dict[str, Any] | None]:
            nonlocal control, write_claimed
            http = schedule.claim(step, reference, body=body)
            if step == "write":
                write_claimed = True
            reply = transport.exchange(step, http)
            _need(type(reply) is ReadResult, "response-invalid")
            control = dict(_check_control(reply.control))
            bounded_json_text(reply.observation, max_bytes=MAX_HTTP_BYTES, max_nodes=20_000, max_depth=24)
            row = policy._object(reply.observation, {"status", "body", "failure"})
            _need(control["reason"] == "none", control["reason"])
            status = row["status"]
            if status is None:
                _need(row["body"] is None and row["failure"] in
                      {"network-unavailable", "tls-failed", "response-invalid", "response-limit", "cancelled"}, "response-invalid")
                raise VersionAllocationError(row["failure"])
            _need(type(status) is int and 100 <= status <= 599 and row["failure"] == "none", "response-invalid")
            if status != 200:
                _need(row["body"] is None, "response-invalid")
                if step == "write" and status in {409, 422}:
                    return status, None
                raise VersionAllocationError({401: "unauthorized", 403: "forbidden", 404: "authority-missing",
                                               429: "rate-limited"}.get(status, "network-unavailable" if status >= 500 else "response-invalid"))
            _need(type(row["body"]) is dict, "response-invalid")
            return status, row["body"]

        def read(step: str, reference: str | None = None) -> dict[str, Any]:
            _, body = take(step, reference)
            _need(body is not None, "response-invalid")
            return body

        _repository_identity(read("repository-before"), authority)
        before_commit = _ref_commit(read("ref-before"))
        _ancestry(read("compare-before", before_commit), checkpoint.commit, before_commit)
        before = _snapshot(read("ledger-before", before_commit), before_commit, authority, checkpoint)
        if pending is not None:
            before.ledger.admit(authority, pending.checkpoint)
        existing = before.ledger.find(request)
        # A read is not durable acknowledgement until the original journal has
        # settled its monotonic checkpoint. Also required on retry/reuse.
        persist(journal.record_checkpoint, authority, before.checkpoint)
        checkpoint = before.checkpoint
        if existing is not None or pending is not None:
            _repository_identity(read("repository-after"), authority)
            if pending is not None:
                _need(existing is not None and existing == pending.reservation, "pending-unresolved")
                persist(journal.mark_resolved, pending, checkpoint)
            return outcome("reserved", "none", existing)
        after = before.ledger.append(request, observations, now=clock())
        pending = PendingAllocation(authority, before.checkpoint, before.blob, after.reservations[-1])
        # Creation/settlement is owned by the adapter. An exception here never
        # authorizes a request, and a partially persisted intent is conserved.
        persist(journal.record_pending, pending)
        try:
            _propose(request, before.ledger.last_version, observations, clock())
        except policy.VersionPolicyError:
            persist(journal.mark_rejected, pending)  # Original positive no-claim fact.
            pending = None
            raise
        status, body = take("write", body=conditional_write_body(pending, after))
        if status in {409, 422}:
            persist(journal.mark_rejected, pending)
            pending = None
            return outcome("conflict", "conditional-conflict")
        _need(body is not None and type(body.get("content")) is dict and type(body.get("commit")) is dict
              and body["content"].get("path") == LEDGER_PATH
              and body["content"].get("sha") == blob_sha(after.to_bytes()), "response-invalid")
        policy._match(body["commit"].get("sha"), policy._SHA)
        acknowledged = True  # HTTP acknowledgement, not durable/native finality.
        after_commit = _ref_commit(read("ref-after"))
        _ancestry(read("compare-after", after_commit), before_commit, after_commit)
        final = _snapshot(read("ledger-after", after_commit), after_commit, authority, before.checkpoint)
        _repository_identity(read("repository-after"), authority)
        existing = final.ledger.find(request)
        _need(existing == pending.reservation, "pending-unresolved")
        persist(journal.record_checkpoint, authority, final.checkpoint)
        checkpoint = final.checkpoint
        persist(journal.mark_resolved, pending, checkpoint)
        return outcome("reserved", "none", existing)
    except (VersionAllocationError, policy.VersionPolicyError, ReadFailure) as error:
        reason = error.reason
    except Exception:
        reason = "response-invalid"
    if pending is not None or write_claimed or reason == "journal-unavailable":
        return outcome("recovery-required", reason)
    return outcome("unavailable" if reason.startswith("authority-") or reason in
                   {"network-unavailable", "tls-failed", "unauthorized", "forbidden", "rate-limited",
                    "not-found-or-inaccessible"} else "rejected", reason)


def prepare_reserved_version_edit(lease: object, checkout: object, expected_revision: str,
                                  expected_baseline: object, reservation: Reservation,
                                  request: AllocationRequest):
    """Prepare ONLY through the original RELEASE_VERSION transaction owner.

    No allocation DTO authorizes this edit. The caller still needs its original
    lease/checkout, mutation authorization and a rechecked source intent. Apply
    uses the unchanged release_version_edit.apply_release_version_edit function.
    After applying, bind the final clean committed source separately before a
    candidate build; do not relabel the pre-edit source as final provenance.
    """
    from . import release_version_edit as edit
    from .version_text import admit_baseline

    _need(type(reservation) is Reservation and type(request) is AllocationRequest
          and reservation.request == request, "candidate-binding-conflict")
    _need(edit._authentic_checkout(checkout), "source-changed")
    baseline = admit_baseline(expected_baseline)
    _need(baseline == checkout.baseline and baseline["savedConfig"]["sha256"] == request.source.configuration_sha256
          and baseline["savedVersion"]["state"] == "present"
          and baseline["savedVersion"]["sha256"] == request.source.version_sha256
          and checkout.values == {"name": request.base_version.name, "build": str(request.base_version.build)}
          and checkout.enabled_platforms == request.enabled_platforms, "source-changed")
    return edit.prepare_release_version_edit(lease, checkout, expected_revision, baseline, "edit",
        {"name": reservation.version.name, "build": str(reservation.version.build)})
