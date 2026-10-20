"""Closed branch DATA and worker comparisons for the existing Git owners.

No new process, input, journal, source grant or lifetime is implemented here.
GitRead lists local refs; only the original GitLocal Apply may publish one new
ref. Shared worker hooks must select these exact types, never an arbitrary
subclass/callback. The core's positive receipt is NOT native settlement.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib

from . import _desktop_git_read_protocol as fields
from . import git_repository_branches as branches
from . import git_service as core
from .git_repository_branches import Branches, BranchIntent, BranchReview, GitBranchesRepository

PUBLICATION = "branch-ref-returned"


@dataclass(frozen=True, slots=True, repr=False)
class Action:
    expected_revision: str
    expected_reference_revision: str
    name: str
    kind: str = field(default="branch-create", init=False)

    def as_dict(self):
        return {"kind": self.kind, "expectedRevision": self.expected_revision,
                "expectedReferenceRevision": self.expected_reference_revision, "name": self.name}


def action(value) -> Action:
    from . import _desktop_git_local_protocol as wire
    try:
        row = fields._keys(value, ("kind", "expectedRevision", "expectedReferenceRevision", "name"))
        wire.require(row["kind"] == "branch-create")
        return Action(fields._hex(row["expectedRevision"]), fields._hex(row["expectedReferenceRevision"]),
                      branches.branch_name(row["name"]))
    except (fields.ProtocolError, core.GitError, UnicodeError, TypeError, ValueError):
        raise wire.ProtocolError(wire._ERROR) from None


def matches_review(request, review) -> None:
    from . import _desktop_git_local_protocol as wire
    wire.require(type(request) is wire.Request and type(request.action) is Action
                 and type(review) is branches.BranchReview and type(review.plan) is branches.BranchCreatePlan
                 and review.digest == branches._review_digest(review.plan))
    plan, selected = review.plan, request.action
    wire.require(plan.action == selected.kind and plan.name == selected.name
                 and plan._snapshot.public.revision == selected.expected_revision
                 and plan.reference_revision == selected.expected_reference_revision)
    if request.phase == "apply":
        wire.require(review.digest == request.review_digest)


def candidate(request, review, intent):
    from . import _desktop_git_local_protocol as wire
    matches_review(request, review)
    wire.require(request.phase == "apply" and type(intent) is branches.BranchIntent)
    _intent(request, intent)
    before, plan = review.plan._snapshot, review.plan
    wire.require(intent == branches.BranchIntent(before.public.revision, plan.reference_revision,
        before.public.branch, before.public.head, before.index_stamp.digest, plan.target, before.public.head))
    raw = wire._encode({"protocol": wire.PROTOCOL, "kind": "candidate", "id": request.id,
        "digest": request.digest, "reviewDigest": review.digest, "intent": intent.as_dict()}, wire.CANDIDATE_LIMIT)
    # The same input owner and exact Candidate identity retain the ACK latch.
    return wire.Candidate(request, intent, raw, hashlib.sha256(raw).hexdigest())


def valid_reason(value) -> bool:
    return type(value) is str and value in core._REASONS | branches.BRANCH_REASONS


def _intent(request, intent) -> None:
    from . import _desktop_git_local_protocol as wire
    wire.require(type(intent) is branches.BranchIntent and intent.action == request.action.kind
        and intent.expected_revision == request.action.expected_revision
        and intent.expected_reference_revision == request.action.expected_reference_revision
        and intent.target_ref == "refs/heads/" + request.action.name
        and type(intent.expected_head) is str and core._OID.fullmatch(intent.expected_head) is not None
        and intent.candidate_ref_oid == intent.expected_head
        and type(intent.expected_index) is str and core._REVISION.fullmatch(intent.expected_index) is not None
        and (intent.expected_ref is None or core._ref(intent.expected_ref)))


def terminal_data(request, status, *, reason: str | None, review, diff, result, publication,
                  first_failure_ns, cleanup_end_ns):
    """Branch-only body inside the unchanged original terminal envelope/clock."""
    from . import _desktop_git_local_protocol as wire
    wire.require(type(request) is wire.Request and type(request.action) is Action
                 and publication in ("not-reported", PUBLICATION))
    if status != "ok":
        wire.require(review is None and diff is None and result is None and publication == "not-reported"
                     and reason is not None and (first_failure_ns is not None or status == "cleanup-unknown"))
        return None
    wire.require(reason is None and diff is None)
    if request.phase == "prepare":
        matches_review(request, review)
        wire.require(result is None and publication == "not-reported" and first_failure_ns is None
                     and cleanup_end_ns == request.hard_end_ns)
        return {"review": review.as_dict()}  # A ref review is not an empty/fabricated diff.
    wire.require(review is None and type(result) is core.MutationResult
                 and result.operation_id == request.id and result.action == request.action.kind
                 and result.settlement == "settled" and result.state in ("succeeded", "failed", "recovery-required"))
    if result.intent is not None:
        _intent(request, result.intent)
    wire.require(publication == "not-reported" or result.intent is not None)
    if result.state == "succeeded":
        wire.require(publication == PUBLICATION and result.reason is None
                     and type(result.observation) is core.Observation and first_failure_ns is None
                     and cleanup_end_ns == request.hard_end_ns
                     and (result.observation.head, result.observation.branch) ==
                         (result.intent.expected_head, result.intent.expected_ref))
    else:
        wire.require(valid_reason(result.reason) and first_failure_ns is not None and result.observation is None)
    return result.as_dict()


def local_session(operation, session) -> bool:
    """A closed branch arm in the actual GitLocal command gate, not a grant."""
    from . import _desktop_git_local_protocol as wire
    return (type(operation.request) is wire.Request and type(operation.request.action) is Action
            and type(operation.repository) is branches.GitBranchesRepository
            and type(session) is branches._BranchSession and session.repository is operation.repository)


def read_session(operation, session) -> bool:
    return (type(operation.request) is fields.Request and operation.request.action.kind == "branches"
            and type(operation.repository) is branches.GitBranchesRepository
            and type(session) is branches._BranchSession and session.repository is operation.repository)


def publication(operation) -> str:
    from . import _desktop_git_local_protocol as wire
    from .desktop_git_local import GitLocalOperation
    wire.require(type(operation) is GitLocalOperation and type(operation.request.action) is Action
                 and operation.request.phase == "apply"
                 and type(operation.repository) is branches.GitBranchesRepository)
    transaction = operation.repository._transaction
    if transaction is None:
        return "not-reported"
    wire.require(type(transaction) is branches._BranchTransaction)
    if transaction.branch_publication is None:
        return "not-reported"
    value, sent = transaction.branch_publication, operation.source.candidate
    wire.require(type(transaction) is branches._BranchTransaction
                 and local_session(operation, transaction.session)
                 and transaction.owner.original is operation and transaction.plan is operation.review.plan
                 and not operation.repository._unknown and not transaction.retained
                 and type(value) is branches._BranchPublication
                 and operation.source.candidate_returned and type(sent) is wire.Candidate
                 and sent.request is operation.request and value.intent is sent.intent is transaction.owner.intent
                 and value.successor is transaction.session.successor
                 and value.successor.name == value.intent.target_ref
                 and value.successor.oid == value.intent.candidate_ref_oid)
    _intent(operation.request, value.intent)
    return PUBLICATION
