"""Closed rename comparisons in the existing GitLocal worker.

No new runner, owner, permission, clock, source capture or journal is here.
Native source projections and the terminal fields are DATA, not substitutes
for the same original SourceBook/ACK/C-A-W/close path.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
import stat

from . import _desktop_git_read_protocol as fields
from . import git_repository_branches as branch
from . import git_repository_rename as rename
from . import git_service as core

STEPS = ("new-log", "old-log", "ref", "head-log", "head", "config")
PUBLICATIONS = ("not-reported", *("rename-" + value + "-returned" for value in STEPS))
PHASES = ("not-published", *(value + "-returned" for value in STEPS))


@dataclass(frozen=True, slots=True, repr=False)
class Action:
    expected_revision: str
    expected_reference_revision: str
    name: str
    kind: str = field(default="branch-rename", init=False)

    def as_dict(self):
        return {"kind": self.kind, "expectedRevision": self.expected_revision,
                "expectedReferenceRevision": self.expected_reference_revision, "name": self.name}


def action(value):
    from . import _desktop_git_local_protocol as wire
    try:
        row = fields._keys(value, ("kind", "expectedRevision", "expectedReferenceRevision", "name"))
        wire.require(row["kind"] == "branch-rename")
        return Action(fields._hex(row["expectedRevision"]), fields._hex(row["expectedReferenceRevision"]),
                      branch.branch_name(row["name"]))
    except (fields.ProtocolError, core.GitError, UnicodeError, TypeError, ValueError):
        raise wire.ProtocolError(wire._ERROR) from None


def core_identity(identity):
    return (identity[0], identity[1], identity[2], identity[6], identity[7], identity[8])


def parent(value, uid):
    fields.require(type(value) is list and len(value) == 9)
    identity = tuple(fields._integer(v, 0 if i < 7 else -(1 << 63),
                    (1 << (64 if i < 7 else 63)) - 1) for i, v in enumerate(value))
    fields.require(identity[0] > 0 and identity[1] > 0 and stat.S_ISDIR(identity[2])
                   and identity[3] == uid and not identity[2] & 0o7022 and identity[5] > 0)
    return identity


@dataclass(frozen=True, slots=True, repr=False)
class RefLocks:
    source_identity: tuple
    target_identity: tuple
    parent_before: tuple
    parent_locked: tuple

    def comparison(self, root, source, name):
        from .git_rename_transaction import BorrowedRefLocks
        to_parent = lambda v: (*core_identity(v), v[3], v[4])
        return BorrowedRefLocks(root, source, "refs/heads/" + name,
            (core_identity(self.source_identity), core_identity(self.target_identity)),
            to_parent(self.parent_before), to_parent(self.parent_locked))


@dataclass(frozen=True, slots=True, repr=False)
class Sources:
    source_ref: str
    locks: RefLocks
    reference: fields.FileSnapshot
    branch_log: fields.FileSnapshot | None
    head_log: fields.FileSnapshot | None


def sources(value, *, phase, root, uid, selected):
    from . import _desktop_git_local_protocol as wire
    try:
        wire.require(type(selected) is Action)
        if phase == "prepare":
            wire.require(value is None)
            return None
        wire.require(phase == "apply")
        row = fields._keys(value, ("sourceRef", "refLocks", "ref", "branchLog", "headLog"))
        source = row["sourceRef"]
        wire.require(type(source) is str and source.startswith("refs/heads/") and core._ref(source))
        old = branch.branch_name(source[len("refs/heads/"):])
        wire.require(old.rsplit("/", 1)[:-1] == selected.name.rsplit("/", 1)[:-1]
                     and old.casefold() != selected.name.casefold())
        locks = fields._keys(row["refLocks"], ("sourceIdentity", "targetIdentity", "parentBefore", "parentLocked"))
        identities = tuple(fields._snapshot(root / ".git" / (name + ".lock"),
            {"identity": locks[key], "sha256": hashlib.sha256(b"").hexdigest()}, uid, 0).identity
            for name, key in ((source, "sourceIdentity"), ("refs/heads/" + selected.name, "targetIdentity")))
        before, after = parent(locks["parentBefore"], uid), parent(locks["parentLocked"], uid)
        wire.require(before[:6] == after[:6] and identities[0][:2] != identities[1][:2]
                     and all(v[2] == 0o100600 and v[6] == 0 for v in identities))
        reference = fields._snapshot(root / ".git" / source, row["ref"], uid, 65)
        logs = tuple(None if row[key] is None else fields._snapshot(root / ".git" / name, row[key], uid, rename.MAX_LOG)
                     for key, name in (("branchLog", "logs/" + source), ("headLog", "logs/HEAD")))
        wire.require((logs[0] is None) == (logs[1] is None))
        return Sources(source, RefLocks(*identities, before, after), reference, *logs)
    except (fields.ProtocolError, core.GitError, UnicodeError, TypeError, ValueError, OverflowError):
        raise wire.ProtocolError(wire._ERROR) from None


def matches_review(request, review):
    from . import _desktop_git_local_protocol as wire
    wire.require(type(request) is wire.Request and type(request.action) is Action
                 and type(review) is rename.RenameReview and type(review.plan) is rename.RenamePlan
                 and review.digest == rename.review_digest(review.plan))
    plan, selected = review.plan, request.action
    wire.require((plan.name, plan._snapshot.public.revision, plan.reference_revision) ==
                 (selected.name, selected.expected_revision, selected.expected_reference_revision))
    original = request.rename_sources
    if request.phase == "prepare":
        wire.require(original is None)
        return
    wire.require(request.phase == "apply" and type(original) is Sources and request.review_digest == review.digest
                 and original.source_ref == plan.source)
    for snapshot, name in ((original.reference, plan.source), (original.branch_log, "logs/" + plan.source),
                           (original.head_log, "logs/HEAD")):
        stamp = plan._controls.file(name)[0]
        wire.require(stamp.kind == "absent" if snapshot is None else
                     stamp.kind == "file" and core_identity(snapshot.identity) == stamp.identity and snapshot.sha256 == stamp.digest)


def valid_reason(value):
    return type(value) is str and value in core._REASONS | rename.REASONS


def valid_intent(request, intent):
    from . import _desktop_git_local_protocol as wire
    wire.require(type(intent) is rename.RenameIntent and type(request.action) is Action
                 and intent.action == request.action.kind and intent.expected_revision == request.action.expected_revision
                 and intent.expected_reference_revision == request.action.expected_reference_revision
                 and core._ref(intent.expected_ref) and intent.expected_ref.startswith("refs/heads/")
                 and intent.target_ref == "refs/heads/" + request.action.name
                 and intent.expected_ref.rsplit("/", 1)[0] == intent.target_ref.rsplit("/", 1)[0]
                 and intent.expected_ref.casefold() != intent.target_ref.casefold()
                 and type(intent.expected_head) is str and core._OID.fullmatch(intent.expected_head) is not None
                 and type(intent.logging) is bool and type(intent.config_moved) is bool)
    for value in (intent.expected_index, intent.original_config, intent.candidate_config, intent.original_log,
                  intent.candidate_log, intent.original_head_log, intent.candidate_head_log):
        wire.require(type(value) is str and core._REVISION.fullmatch(value) is not None)
    wire.require(intent.config_moved or intent.candidate_config == intent.original_config)
    if not intent.logging:
        wire.require(all(value == core._ABSENT.digest for value in (intent.original_log, intent.candidate_log,
                     intent.original_head_log, intent.candidate_head_log)))


def candidate(request, review, intent):
    from . import _desktop_git_local_protocol as wire
    matches_review(request, review)
    wire.require(request.phase == "apply")
    valid_intent(request, intent)
    plan, before = review.plan, review.plan._snapshot
    wire.require((intent.expected_ref, intent.expected_head, intent.expected_index, intent.original_config,
                  intent.original_log, intent.original_head_log, intent.config_moved, intent.logging) ==
                 (plan.source, before.public.head, before.index_stamp.digest, plan._controls.file("config")[0].digest,
                  plan._controls.file("logs/" + plan.source)[0].digest, plan._controls.file("logs/HEAD")[0].digest,
                  plan._controls.config_candidate is not None, plan._controls.logging))
    raw = wire._encode({"protocol": wire.PROTOCOL, "kind": "candidate", "id": request.id,
        "digest": request.digest, "reviewDigest": review.digest, "intent": intent.as_dict()}, wire.CANDIDATE_LIMIT)
    return wire.Candidate(request, intent, raw, hashlib.sha256(raw).hexdigest())


@dataclass(frozen=True, slots=True, repr=False)
class Progress:
    phase: str
    retained: tuple[str, ...]

    def valid(self, publication):
        return (publication in PUBLICATIONS and self.phase == PHASES[PUBLICATIONS.index(publication)]
            and type(self.retained) is tuple and len(self.retained) <= 1 and self.retained == tuple(sorted(set(self.retained)))
            and all(type(path) is str and re.fullmatch(r"\.git/mrk-git-[A-Za-z0-9_-]{1,64}/index", path)
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
    wire.require(review is None and type(result) is core.MutationResult and result.operation_id == request.id
                 and result.action == request.action.kind and result.settlement == "settled"
                 and result.state in ("succeeded", "failed", "recovery-required")
                 and type(progress) is Progress and progress.valid(publication))
    if result.intent is not None:
        valid_intent(request, result.intent)
    wire.require(publication == "not-reported" or result.intent is not None and
                 STEPS[PUBLICATIONS.index(publication) - 1] in rename.steps(result.intent))
    if result.state == "succeeded":
        wire.require(result.intent is not None and publication == "rename-" + rename.steps(result.intent)[-1] + "-returned"
                     and not progress.retained and result.reason is None and type(result.observation) is core.Observation
                     and (result.observation.head, result.observation.branch) == (result.intent.expected_head, result.intent.target_ref)
                     and first_failure_ns is None and cleanup_end_ns == request.hard_end_ns)
    else:
        wire.require(valid_reason(result.reason) and first_failure_ns is not None and result.observation is None
                     and (result.state == "recovery-required" and result.intent is not None or
                          result.state == "failed" and publication == "not-reported" and not progress.retained))
    return {**result.as_dict(), "effectPhase": progress.phase, "retainedPaths": list(progress.retained)}


def local_session(operation, session):
    from . import _desktop_git_local_protocol as wire
    return (type(operation.request) is wire.Request and type(operation.request.action) is Action
            and type(operation.repository) is rename.GitRenameRepository
            and type(session) is rename._RenameSession and session.repository is operation.repository)


def command_identity(operation, session, args):
    from . import _desktop_git_local_protocol as wire
    wire.require(local_session(operation, session))
    expected = session.execution_command
    if expected is None:
        return None
    wire.require(expected[0] == tuple(args))
    return expected[2]


def returned_command(operation, session, args, result):
    from . import _desktop_git_local_protocol as wire
    from .git_rename_transaction import RenameTransaction
    wire.require(local_session(operation, session))
    if session.execution_command is None:
        return
    transaction = operation.repository._transaction
    wire.require(type(transaction) is RenameTransaction and transaction.session is session
                 and transaction.owner.original is operation and operation.pending is not None and operation.pending.claimed)
    if result.returncode == 0:
        transaction.command_did_return(args, result)


def prepare_or_apply(operation):
    from . import _desktop_git_local_protocol as wire
    wire.require(type(operation.request.action) is Action and operation.entered and operation.source.go_returned)
    selected, original = operation.request.action, operation.request.rename_sources
    locks = None if original is None else original.locks.comparison(operation.request.root, original.source_ref, selected.name)
    operation.repository = rename.GitRenameRepository(operation.request.root, git_executable=wire.TOOL_PATH,
        work_end=operation.source.work_end, cancellation=operation.guard, _run=operation.command, _ref_locks=locks)
    if operation.request.phase == "prepare":
        operation.review = operation.repository.prepare_rename(selected.name, expected_revision=selected.expected_revision,
            expected_reference_revision=selected.expected_reference_revision)
        matches_review(operation.request, operation.review)
        return
    wire.require(operation.request.phase == "apply" and type(original) is Sources)

    @core._session_boundary
    def apply_current(repository):
        wire.require(not repository._apply_entered)
        repository._apply_entered = True
        session = repository._session()
        plan = repository._capture_rename(session, selected.name, selected.expected_revision, selected.expected_reference_revision)
        operation.review = rename.RenameReview(plan, rename.review_digest(plan))
        matches_review(operation.request, operation.review)
        plan._used = True
        return repository._apply_captured(session, operation.review, operation)

    operation.result = apply_current(operation.repository)
    operation.rename_state.capture_progress()
