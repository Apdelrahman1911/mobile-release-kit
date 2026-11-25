"""Closed local fast-forward DATA in the original GitLocal worker.

No process, source grant, Store, consent, clock or separate command dispatcher.
Only the fixed original parent hooks may select these types. Source snapshots
and positive core receipts are comparisons, not native admission or finality.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
import stat

from . import _desktop_git_read_protocol as fields
from . import git_repository_switch as shared
from . import git_repository_fast_forward as ff
from . import git_service as core

PUBLICATIONS = ("not-reported", "ff-worktree-returned", "ff-index-returned", "ff-ref-returned")
PHASES = ("not-published", "worktree-returned", "index-returned", "ref-returned")


@dataclass(frozen=True, slots=True, repr=False)
class Action:
    expected_revision: str
    expected_reference_revision: str
    target_ref: str
    target_oid: str
    kind: str = field(default="fast-forward", init=False)

    def as_dict(self):
        return {"kind": self.kind, "expectedRevision": self.expected_revision,
                "expectedReferenceRevision": self.expected_reference_revision, "targetRef": self.target_ref, "targetOid": self.target_oid}


def action(value) -> Action:
    from . import _desktop_git_local_protocol as wire
    try:
        row = fields._keys(value, ("kind", "expectedRevision", "expectedReferenceRevision", "targetRef", "targetOid"))
        wire.require(row["kind"] == "fast-forward")
        wire.require(ff.tracking_ref(row["targetRef"]) and type(row["targetOid"]) is str and core._OID.fullmatch(row["targetOid"]))
        return Action(fields._hex(row["expectedRevision"]), fields._hex(row["expectedReferenceRevision"]),
                      row["targetRef"], row["targetOid"])
    except (fields.ProtocolError, core.GitError, UnicodeError, TypeError, ValueError):
        raise wire.ProtocolError(wire._ERROR) from None


def _parent(value, uid):
    fields.require(type(value) is list and len(value) == 9)
    identity = tuple(fields._integer(v, 0 if i < 7 else -(1 << 63),
                     (1 << (64 if i < 7 else 63)) - 1) for i, v in enumerate(value))
    fields.require(identity[0] > 0 and identity[1] > 0 and stat.S_ISDIR(identity[2])
                   and identity[3] == uid and not identity[2] & 0o7022 and identity[5] > 0)
    return identity


def core_identity(identity):
    return (identity[0], identity[1], identity[2], identity[6], identity[7], identity[8])


@dataclass(frozen=True, slots=True, repr=False)
class TargetLock:
    identity: tuple[int, ...]
    parent_before: tuple[int, ...]
    parent_locked: tuple[int, ...]

    def comparison(self, root, target_ref):
        from .git_fast_forward_transaction import BorrowedTrackingLock
        parent = lambda v: (*core_identity(v), v[3], v[4])
        return BorrowedTrackingLock(root, target_ref, core_identity(self.identity),
                                  parent(self.parent_before), parent(self.parent_locked))


@dataclass(frozen=True, slots=True, repr=False)
class Sources:
    lock: TargetLock
    log: fields.FileSnapshot | None
    branch_log: fields.FileSnapshot | None
    reference: fields.FileSnapshot
    files: tuple[fields.FileSnapshot, ...]


def sources(value, *, phase, root, uid, selected) -> Sources | None:
    """Only the fast-forward sealed request has this extra required field.

    Prepare is read-only and has no acquired target lock. Apply receives the
    actual native originals captured from its retained joined review. A parsed
    projection cannot nominate the native SourceBook or create that lock.
    """
    from . import _desktop_git_local_protocol as wire
    try:
        wire.require(type(selected) is Action)
        if phase == "prepare":
            wire.require(value is None)
            return None
        wire.require(phase == "apply")
        row = fields._keys(value, ("targetLock", "headLog", "branchLog", "currentRef", "files"))
        lock = fields._keys(row["targetLock"], ("identity", "parentBefore", "parentLocked"))
        identity = fields._snapshot(root / ".git" / (selected.target_ref + ".lock"),
            {"identity": lock["identity"], "sha256": hashlib.sha256(b"").hexdigest()}, uid, 0).identity
        before, after = _parent(lock["parentBefore"], uid), _parent(lock["parentLocked"], uid)
        wire.require(stat.S_IMODE(identity[2]) == 0o600 and identity[6] == 0 and before[:6] == after[:6])
        log = None if row["headLog"] is None else fields._snapshot(root / ".git/logs/HEAD", row["headLog"], uid, shared.MAX_LOG)
        ref = fields._keys(row["currentRef"], ("path", "snapshot"))
        wire.require(type(ref["path"]) is str and core._ref(ref["path"]))
        reference = fields._snapshot(root / ".git" / ref["path"], ref["snapshot"], uid, 65)
        branch_log = None if row["branchLog"] is None else fields._snapshot(root / ".git/logs" / ref["path"], row["branchLog"], uid, shared.MAX_LOG)
        values = row["files"]
        wire.require(type(values) is list and len(values) <= shared.MAX_CHANGED)
        names, snapshots = [], []
        for value in values:
            entry = fields._keys(value, ("path", "snapshot"))
            name = core._paths([entry["path"]])[0]
            wire.require(not core._sensitive_path(name) and len(name.split("/")) <= 32)
            names.append(name)
            snapshots.append(fields._snapshot(root / name, entry["snapshot"], uid, core.MAX_FILE_BYTES))
        wire.require(names == sorted(set(names)) and sum(v.identity[6] for v in snapshots) <= shared.MAX_BYTES)
        return Sources(TargetLock(identity, before, after), log, branch_log, reference, tuple(snapshots))
    except (fields.ProtocolError, core.GitError, UnicodeError, TypeError, ValueError, OverflowError):
        raise wire.ProtocolError(wire._ERROR) from None


def matches_review(request, review) -> None:
    from . import _desktop_git_local_protocol as wire
    wire.require(type(request) is wire.Request and type(request.action) is Action
                 and type(review) is ff.FastForwardReview and type(review.plan) is ff.FastForwardPlan
                 and review.digest == ff.review_digest(review.plan))
    plan, selected = review.plan, request.action
    wire.require((plan.action, plan.target_ref, plan.target_oid, plan._snapshot.public.revision, plan.reference_revision) ==
                 (selected.kind, selected.target_ref, selected.target_oid, selected.expected_revision, selected.expected_reference_revision))
    if request.phase == "prepare":
        wire.require(request.fast_forward_sources is None)
        return
    original = request.fast_forward_sources
    wire.require(request.phase == "apply" and type(original) is Sources and request.review_digest == review.digest
                 and tuple(str(row.path.relative_to(request.root)) for row in original.files) == plan.changed)
    stamps = dict(plan._footprint.files)
    for row in original.files:
        stamp = stamps[str(row.path.relative_to(request.root))]
        wire.require(core_identity(row.identity) == stamp.identity and row.sha256 == stamp.digest)
    wire.require(original.reference.path == request.root / ".git" / plan._snapshot.public.branch
                 and original.reference.sha256 == core._digest((plan._snapshot.public.head + "\n").encode("ascii")))
    for snapshot, log in ((original.log, plan._log.original), (original.branch_log, plan._branch_log.original)):
        wire.require(log.kind == "absent" if snapshot is None else
                     log.kind == "file" and core_identity(snapshot.identity) == log.identity and snapshot.sha256 == log.digest)


def valid_reason(value) -> bool:
    return type(value) is str and value in core._REASONS | shared._REASONS | ff.REASONS


def _intent(request, intent):
    from . import _desktop_git_local_protocol as wire
    wire.require(type(intent) is ff.FastForwardIntent and type(request.action) is Action
                 and intent.action == "fast-forward" and intent.expected_revision == request.action.expected_revision
                 and intent.expected_reference_revision == request.action.expected_reference_revision
                 and intent.target_ref == request.action.target_ref and intent.target_oid == request.action.target_oid
                 and core._ref(intent.expected_ref) and core._OID.fullmatch(intent.expected_head)
                 and len(intent.expected_head) == len(intent.target_oid) and intent.expected_head != intent.target_oid
                 and type(intent.head_log_enabled) is bool and type(intent.branch_log_enabled) is bool)
    for value in (intent.expected_index, intent.candidate_index, intent.original_head,
                  intent.original_head_log, intent.original_branch_log, intent.footprint):
        wire.require(type(value) is str and core._REVISION.fullmatch(value) is not None)
    wire.require(intent.original_head == core._digest(("ref: " + intent.expected_ref + "\n").encode("utf-8")))


def candidate(request, review, intent):
    from . import _desktop_git_local_protocol as wire
    matches_review(request, review)
    wire.require(request.phase == "apply")
    _intent(request, intent)
    plan, before = review.plan, review.plan._snapshot
    wire.require((intent.expected_ref, intent.expected_head, intent.expected_index, intent.target_ref, intent.target_oid,
                  intent.original_head_log, intent.original_branch_log, intent.head_log_enabled, intent.branch_log_enabled, intent.footprint) ==
                 (before.public.branch, before.public.head, before.index_stamp.digest, plan.target_ref, plan.target_oid,
                  plan._log.original.digest, plan._branch_log.original.digest, plan._log.enabled, plan._branch_log.enabled,
                  shared._hash({"source": plan._footprint.comparison(), "target": plan._target_hashes})))
    raw = wire._encode({"protocol": wire.PROTOCOL, "kind": "candidate", "id": request.id,
        "digest": request.digest, "reviewDigest": review.digest, "intent": intent.as_dict()}, wire.CANDIDATE_LIMIT)
    return wire.Candidate(request, intent, raw, hashlib.sha256(raw).hexdigest())


@dataclass(frozen=True, slots=True, repr=False)
class Progress:
    phase: str
    retained: tuple[str, ...]

    def valid(self, publication):
        return (publication in PUBLICATIONS and self.phase == PHASES[PUBLICATIONS.index(publication)]
            and type(self.retained) is tuple and len(self.retained) <= 5
            and self.retained == tuple(sorted(set(self.retained)))
            and all(type(path) is str and re.fullmatch(
                r"\.git/mrk-git-[A-Za-z0-9_-]{1,64}/(?:index|execution-index|checkout-mode)", path)
                    is not None for path in self.retained))


def terminal_data(request, status, *, reason, review, diff, result, publication, progress,
                  first_failure_ns, cleanup_end_ns):
    from . import _desktop_git_local_protocol as wire
    wire.require(type(request) is wire.Request and type(request.action) is Action and publication in PUBLICATIONS)
    if status != "ok":
        wire.require(review is None and diff is None and result is None and progress is None
                     and publication == "not-reported" and reason is not None
                     and (first_failure_ns is not None or status == "cleanup-unknown"))
        return None
    wire.require(reason is None and diff is None)
    if request.phase == "prepare":
        matches_review(request, review)
        wire.require(result is None and progress is None and publication == "not-reported"
                     and first_failure_ns is None and cleanup_end_ns == request.hard_end_ns)
        return {"review": review.as_dict()}
    wire.require(review is None and type(result) is core.MutationResult
                 and result.operation_id == request.id and result.action == request.action.kind
                 and result.settlement == "settled" and result.state in ("succeeded", "failed", "recovery-required")
                 and type(progress) is Progress and progress.valid(publication))
    if result.intent is not None:
        _intent(request, result.intent)
    wire.require(publication == "not-reported" or result.intent is not None)
    if result.state == "succeeded":
        wire.require(publication == "ff-ref-returned" and not progress.retained and result.reason is None
                     and type(result.observation) is core.Observation and first_failure_ns is None
                     and cleanup_end_ns == request.hard_end_ns
                     and (result.observation.head, result.observation.branch) == (result.intent.target_oid, result.intent.expected_ref))
    else:
        wire.require(valid_reason(result.reason) and first_failure_ns is not None and result.observation is None)
        wire.require((result.state == "recovery-required" and result.intent is not None) or
                     (result.state == "failed" and publication == "not-reported" and not progress.retained))
    return {**result.as_dict(), "effectPhase": progress.phase, "retainedPaths": list(progress.retained)}


def local_session(operation, session):
    from . import _desktop_git_local_protocol as wire
    return (type(operation.request) is wire.Request and type(operation.request.action) is Action
            and type(operation.repository) is ff.GitFastForwardRepository
            and type(session) is ff._FastForwardSession and session.repository is operation.repository)


def command_identity(operation, session, args):
    from . import _desktop_git_local_protocol as wire
    wire.require(local_session(operation, session))
    expected = session.execution_command
    if expected is None:
        return None
    wire.require(expected[0] == tuple(args))
    return expected[2]  # The actual fixed transaction retained this object.


def returned_command(operation, session, args, result):
    """Exact parent call AFTER original C/A/W return, BEFORE source_post.

    A fake result alone cannot call the production route. The original parent
    has already matched its pending command and actual ledger for this call.
    """
    from . import _desktop_git_local_protocol as wire
    from .git_fast_forward_transaction import FastForwardTransaction
    wire.require(local_session(operation, session))
    if session.execution_command is None:
        return
    transaction = operation.repository._transaction
    wire.require(type(transaction) is FastForwardTransaction and transaction.session is session
                 and transaction.owner.original is operation and operation.pending is not None
                 and operation.pending.claimed)
    if result.returncode == 0:
        transaction.command_did_return(args, result)


def prepare_or_apply(operation):
    """One fresh original capture on Apply, not a deserialized plan/grant."""
    from . import _desktop_git_local_protocol as wire
    wire.require(type(operation.request.action) is Action and operation.entered and operation.source.go_returned)
    selected = operation.request.action
    original = operation.request.fast_forward_sources
    lock = None if original is None else original.lock.comparison(operation.request.root, selected.target_ref)
    operation.repository = ff.GitFastForwardRepository(operation.request.root, git_executable=wire.TOOL_PATH,
        work_end=operation.source.work_end, cancellation=operation.guard, _run=operation.command, _target_lock=lock)
    if operation.request.phase == "prepare":
        operation.review = operation.repository.prepare_fast_forward(selected.target_ref, selected.target_oid, expected_revision=selected.expected_revision,
            expected_reference_revision=selected.expected_reference_revision)
        matches_review(operation.request, operation.review)
        return
    wire.require(operation.request.phase == "apply" and type(original) is Sources)
    repository = operation.repository

    @core._session_boundary
    def apply_current(repository):
        wire.require(not repository._apply_entered)
        repository._apply_entered = True
        session = repository._session()
        plan = repository._capture_fast_forward(session, selected.target_ref, selected.target_oid, selected.expected_revision,
                                         selected.expected_reference_revision)
        operation.review = ff.FastForwardReview(plan, ff.review_digest(plan))
        matches_review(operation.request, operation.review)
        plan._used = True
        return repository._apply_captured(session, operation.review, operation)

    operation.result = apply_current(repository)
    operation.fast_forward_state.capture_progress()
