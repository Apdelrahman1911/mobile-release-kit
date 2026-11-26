"""Closed local branch list/create over the existing GitLocal transaction.

This module neither admits a native invocation nor owns a durable journal.
The actual caller must retain the same GitLocal publisher/source/process/Store
owners. One standard expected-absent update-ref creates a branch at the reviewed
HEAD. There is no switch, rename, upstream, deletion, reset or arbitrary ref API.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from . import git_repository_local as local
from . import git_repository_read as read
from . import git_service as core
from .owned_process import ProcessError

MAX_BRANCHES = 256
MAX_BRANCH_BYTES = 384 * 1024
BRANCH_REASONS = frozenset(("branch-exists", "branch-parent-missing", "branch-identity-required", "unborn-head"))
_FORMAT = "%(refname)%00%(objectname)%00%(symref)%00"
_LIST = ("for-each-ref", "--sort=refname", "--count=257", "--format=" + _FORMAT, "--", "refs/heads/")
_MESSAGE = "MRK: create reviewed branch"
_LOG_LIMIT = 2048


class BranchError(core.GitError):
    """Fixed branch-only refusal; wire adapters must explicitly admit its code."""
    def __init__(self, reason: str):
        core._need(reason in BRANCH_REASONS, "invalid-input")
        super().__init__("invalid-input")
        self.reason = reason


def branch_name(value) -> str:
    # New names use a small, unambiguous ASCII subset. Existing branch listing
    # still accepts the original bounded UTF-8 ref grammar.
    core._need(type(value) is str and 1 <= len(value) <= 255
               and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", value) is not None
               and len(value.split("/")) <= 16 and core._ref("refs/heads/" + value), "invalid-input")
    core._need(core._SECRET.search(value.encode("ascii")) is None, "sensitive-content")
    return value


@dataclass(frozen=True, slots=True)
class Branch:
    ref: str
    oid: str

    def as_dict(self):
        return {"ref": self.ref, "oid": self.oid}


@dataclass(frozen=True, slots=True)
class Branches:
    revision: str
    reference_revision: str
    head: str | None
    branch: str | None
    branches: tuple[Branch, ...]

    def as_dict(self):
        return {"revision": self.revision, "referenceRevision": self.reference_revision,
                "head": self.head, "branch": self.branch, "branches": [row.as_dict() for row in self.branches],
                "basis": "local-refs-no-fetch"}


def _rows(raw: bytes) -> tuple[Branch, ...]:
    core._need(type(raw) is bytes and len(raw) <= MAX_BRANCH_BYTES
               and (not raw or raw.endswith(b"\n")), "response-invalid")
    result = []
    for line in raw.splitlines():
        fields = line.split(b"\0")
        core._need(len(fields) == 4 and fields[2:] == [b"", b""], "unsupported-repository")
        ref = read._decoded(fields[0])
        core._need(core._SECRET.search(fields[0]) is None, "sensitive-content")
        oid = core._oid(fields[1])
        core._need(core._ref(ref) and len(ref.split("/")) <= read.MAX_REF_DEPTH, "unsupported-repository")
        core._need(not result or result[-1].ref < ref, "response-invalid")
        result.append(Branch(ref, oid))
        core._need(len(result) <= MAX_BRANCHES, "limit")
    return tuple(result)


def _absent_target(rows: tuple[Branch, ...], target: str) -> None:
    folded = target.casefold()
    for row in rows:
        other = row.ref.casefold()
        if folded == other or folded.startswith(other + "/") or other.startswith(folded + "/"):
            raise BranchError("branch-exists")


def _directory(path: Path) -> tuple[int, ...] | None:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    core._need(stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid()
               and not before.st_mode & 0o7022, "unsupported-repository")
    return (*core._identity(before), before.st_uid, before.st_gid)


@dataclass(frozen=True, slots=True, repr=False)
class _LogPolicy:
    enabled: bool
    path: Path
    parents: tuple[tuple[Path, tuple[int, ...] | None], ...]
    identity: core.CommitIdentity

    def comparison(self):
        return {"enabled": self.enabled, "parents": [(str(p), i) for p, i in self.parents],
                "identity": (self.identity.name, self.identity.email)}


def _local_identity(config: dict) -> core.CommitIdentity:
    # This supported profile never guesses a login/host identity or loads
    # ambient global config. Refuse other identity policies rather than silently
    # overriding them. Explicit env values below equal these retained local
    # user.name/user.email settings, not an invented application identity.
    if any(key.startswith(("author.", "committer.")) for key in config):
        raise BranchError("branch-identity-required")
    try:
        name, email = config["user.name"], config["user.email"]
        core._need(len(name) == len(email) == 1, "invalid-input")
        identity = core.CommitIdentity(name[0].decode("utf-8", "strict"), email[0].decode("utf-8", "strict"))
        identity.validate()
        # Refuse spellings Git may trim/sanitize, before any publication.
        # This is deliberately a supported subset, not an RFC identity parser.
        core._need(identity.name[0].isalnum() and identity.name[-1].isalnum()
                   and not any(c in "\"'\\" for c in identity.name)
                   and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+%-]*@[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]",
                                    identity.email) is not None, "invalid-input")
        core._need(core._SECRET.search(name[0] + b"\n" + email[0]) is None, "invalid-input")
    except (KeyError, UnicodeError, core.GitError):
        raise BranchError("branch-identity-required") from None
    return identity


def _logging(git_dir: Path, target: str, config: dict) -> _LogPolicy:
    values = config.get("core.logallrefupdates", (b"true",))
    core._need(values in ((b"true",), (b"false",)), "unsupported-repository")
    identity = _local_identity(config)
    path = git_dir / "logs" / target
    parents, missing = [], False
    for parent in reversed(path.parents):
        if parent == git_dir or not parent.is_relative_to(git_dir):
            continue
        observed = None if missing else _directory(parent)
        parents.append((parent, observed))
        missing |= observed is None
    if values == (b"true",) and missing:
        raise BranchError("branch-parent-missing")
    if not missing:
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        else:
            # A leftover reflog is not ours to overwrite, append or repair.
            raise BranchError("branch-exists")
    return _LogPolicy(values == (b"true",), path, tuple(parents), identity)


@dataclass(slots=True, repr=False)
class BranchCreatePlan:
    name: str
    reference_revision: str
    _key: object
    _snapshot: core._Snapshot
    _logging: _LogPolicy
    _used: bool = False
    action: str = field(default="branch-create", init=False)

    @property
    def target(self) -> str:
        return "refs/heads/" + self.name

    def public(self) -> dict:
        source = self._snapshot.public
        return {"action": self.action, "name": self.name, "targetRef": self.target,
                "expectedRevision": source.revision, "expectedReferenceRevision": self.reference_revision,
                "head": source.head, "branch": source.branch, "expectedIndex": self._snapshot.index_stamp.digest}


def _review_digest(plan: BranchCreatePlan) -> str:
    core._need(type(plan) is BranchCreatePlan, "invalid-input")
    value = {"review": plan.public(), "logging": plan._logging.comparison()}
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(b"mrk-git-branch-create-review/1\0" + raw).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class BranchReview:
    plan: BranchCreatePlan
    digest: str

    def as_dict(self) -> dict:
        return {**self.plan.public(), "reviewDigest": self.digest}


@dataclass(frozen=True, slots=True)
class BranchIntent:
    expected_revision: str
    expected_reference_revision: str
    expected_ref: str | None
    expected_head: str
    expected_index: str
    target_ref: str
    candidate_ref_oid: str
    action: str = field(default="branch-create", init=False)

    def as_dict(self) -> dict:
        return {"action": self.action, "expectedRevision": self.expected_revision,
                "expectedReferenceRevision": self.expected_reference_revision, "expectedRef": self.expected_ref,
                "expectedHead": self.expected_head, "expectedIndex": self.expected_index,
                "targetRef": self.target_ref, "expectedTargetAbsent": True, "candidateRefOid": self.candidate_ref_oid}


@dataclass(frozen=True, slots=True, repr=False)
class _BranchPublication:
    """Comparison after a positive original CAS/full checks, not native finality."""
    intent: BranchIntent
    successor: local._RefSuccessor
    log_stamp: core._Stamp | None


class _BranchHandoff:
    def __init__(self, repository, plan, original):
        self.repository, self.plan, self.original = repository, plan, original
        self.operation_id = core._text(original.operation_id, 128)
        self.entered = self.acknowledged = False
        self.intent = None

    def check_current(self, root, action, revision):
        core._need((root, action, revision) == (self.repository.root, self.plan.action, self.plan._snapshot.public.revision),
                   "authorization")
        self.original.check_current(root, action, revision)

    def record_intent(self, intent):
        plan = self.plan
        source = plan._snapshot
        expected = BranchIntent(source.public.revision, plan.reference_revision, source.public.branch,
                                source.public.head, source.index_stamp.digest, plan.target, source.public.head)
        core._need(not self.entered and type(intent) is BranchIntent and intent == expected, "authorization")
        self.entered, self.intent = True, intent
        self.original.record_intent(intent)
        self.repository._transaction.session.guard_current()
        self.acknowledged = True

    def publication_ready(self):
        core._need(self.acknowledged and self.intent is not None, "authorization")


class _BranchTransaction(local._LocalTransaction):
    def __init__(self, session, original, plan, owner):
        super().__init__(session, original, plan, owner)
        self.branch_publication = None

    def acquire(self):
        self.session.require_ref_parent(self.plan.target)
        super().acquire()

    def accept_publication(self):
        self.owner.publication_ready()
        self.check_original()
        core._need(self.branch_publication is None and self.session.successor is not None,
                   "recovery-required")
        self.branch_publication = _BranchPublication(self.owner.intent, self.session.successor, self.session.log_stamp)


class _BranchSession(local._LocalSession):
    def __init__(self, repository):
        super().__init__(repository)
        self.logging = None
        self.log_stamp = None
        self.log_parent = None

    def _check_logging(self, *, accept_successor=False):
        policy = self.logging
        if policy is None:
            return
        missing = False
        for path, before in policy.parents:
            after = None if missing else _directory(path)
            missing |= after is None
            if policy.enabled and path == policy.path.parent and (accept_successor or self.log_stamp is not None):
                core._need(before is not None and after is not None and before[:3] == after[:3]
                           and before[6:] == after[6:], "stale-observation")
                if self.log_parent is not None:
                    core._need(after == self.log_parent, "stale-observation")
            else:
                core._need(before == after, "stale-observation")
        if missing:
            core._need(not policy.enabled, "stale-observation")
            return
        if not policy.enabled or not (accept_successor or self.log_stamp is not None):
            try:
                policy.path.lstat()
            except FileNotFoundError:
                return
            raise core.GitError("stale-observation")
        stamp, raw = core._read(policy.path, _LOG_LIMIT)
        plan = self.repository._active_plan
        core._need(type(plan) is BranchCreatePlan and plan._snapshot.public.head is not None, "authorization")
        head = plan._snapshot.public.head.encode("ascii")
        identity = (policy.identity.name + " <" + policy.identity.email + ">").encode("utf-8")
        pattern = (re.escape(b"0" * len(head) + b" " + head + b" " + identity + b" ")
                   + rb"[0-9]{1,12} [+-][0-9]{4}\t" + re.escape(_MESSAGE.encode("ascii")) + rb"\n")
        core._need(stamp.kind == "file" and re.fullmatch(pattern, raw) is not None, "recovery-required")
        info = policy.path.lstat()
        core._need(info.st_uid == os.getuid() and info.st_nlink == 1 and not info.st_mode & 0o7022
                   and core._identity(info) == stamp.identity, "recovery-required")
        if self.log_stamp is not None:
            core._need(stamp == self.log_stamp, "stale-observation")
        else:
            core._need(accept_successor, "authorization")
            self.log_stamp, self.log_parent = stamp, _directory(policy.path.parent)

    def check_original(self):
        super().check_original()
        self._check_logging()

    def command_spec(self, args, *, index=None, identity=None):
        core._need(type(args) is list and args and all(type(value) is str for value in args), "invalid-input")
        is_list = args == list(_LIST)
        is_create = args and args[0] == "update-ref"
        if not is_list and not is_create:
            return super().command_spec(args, index=index, identity=identity)
        core._need(not self.initial_config and not self.recensusing and self.config is not None
                   and index is None and identity is None, "invalid-input")
        seed = ["ls-files", "--stage", "-z"]
        argv, environment = read._ReadSession.command_spec(self, seed)
        if is_create:
            transaction, plan = self.repository._transaction, self.repository._active_plan
            core._need(type(transaction) is _BranchTransaction and transaction.session is self
                       and type(plan) is BranchCreatePlan and self.logging == plan._logging
                       and not transaction.retained and transaction.branch_publication is None, "authorization")
            transaction.owner.publication_ready()
            transaction.config_lock.check()
            head = plan._snapshot.public.head
            core._need(head is not None and args == ["update-ref", "--no-deref", "-m", _MESSAGE,
                       plan.target, head, "0" * len(head)], "invalid-input")
            argv[argv.index("--git-dir=" + str(self.frozen.root))] = "--git-dir=" + str(self.git_dir)
            environment.update(GIT_COMMITTER_NAME=self.logging.identity.name, GIT_COMMITTER_EMAIL=self.logging.identity.email)
        return [*argv[:-len(seed)], *args], environment

    def _accept_ref_successor(self):
        plan, transaction = self.repository._active_plan, self.repository._transaction
        core._need(type(plan) is BranchCreatePlan and type(transaction) is _BranchTransaction
                   and transaction.session is self and self.successor is None, "recovery-required")
        transaction.owner.publication_ready()
        self._resolved_head = None
        current = read._inventory(self.git_dir, self.checkpoint, self.names)
        files = {name: (stamp, raw) for name, stamp, raw in current.files}
        selected = files.get(plan.target)
        head = plan._snapshot.public.head
        core._need(head is not None and selected is not None and selected[0].kind == "file"
                   and selected[1] == (head + "\n").encode("ascii"), "recovery-required")
        parent = dict(current.directories).get(plan.target.rsplit("/", 1)[0])
        core._need(parent is not None, "recovery-required")
        successor = local._RefSuccessor(plan.target, head, selected[0], parent)
        core._need(local._inventory_matches(self.originals, current, objects_written=False, successor=successor),
                   "recovery-required")
        self._check_logging(accept_successor=True)
        self.successor = successor
        self.frozen.write(plan.target, selected[1])
        self.check_original()

    def catalog(self) -> tuple[Branch, ...]:
        self.guard_current()
        self.check_original()
        self._check_frozen()
        _, raw = self.git(list(_LIST), limit=MAX_BRANCH_BYTES)
        rows = _rows(raw)
        width = 64 if self.config.get("extensions.objectformat", (b"sha1",)) == (b"sha256",) else 40
        core._need(all(len(row.oid) == width for row in rows), "response-invalid")
        head, branch = self.head()
        if branch is not None:
            current = next((row.oid for row in rows if row.ref == branch), None)
            core._need(current == head, "response-invalid")
        self.check_original()
        self.guard_current()
        self._check_frozen()
        return rows


class GitBranchesRepository(local.GitLocalRepository):
    """Closed core facade; the native fixed worker retains the actual owners."""
    def _session(self):
        core._need(not self._unknown, "unknown")
        session = _BranchSession(self)
        self._active_sessions.append(session)
        session.discover()
        return session

    @core._session_boundary
    def branches(self, *, expected_revision: str) -> Branches:
        session = self._session()
        before = session.snapshot()
        self._expected(before, expected_revision)
        rows = session.catalog()
        self._expected(session.snapshot(), expected_revision)
        return Branches(expected_revision, session.reference_revision(before.public), before.public.head,
                        before.public.branch, rows)

    def _capture(self, session, name, expected_revision, expected_reference_revision):
        name = branch_name(name)
        core._need(type(expected_reference_revision) is str and core._REVISION.fullmatch(expected_reference_revision),
                   "invalid-input")
        before = session.snapshot()
        self._expected(before, expected_revision)
        core._need(session.reference_revision(before.public) == expected_reference_revision, "stale-observation")
        self._policy(before, "branch-create")
        core._need("required-signing" not in before.public.restrictions, "required-signing")
        if before.public.head is None:
            raise BranchError("unborn-head")
        target = "refs/heads/" + name
        _absent_target(session.catalog(), target)
        directories = dict(session.originals.directories)
        # An empty namespace has no for-each-ref row, but it is not an absent
        # destination. Git may remove such a directory while creating a ref;
        # this operation has no authority to retire any original namespace.
        if any(path.casefold() == target.casefold() for path in directories):
            raise BranchError("branch-exists")
        if target.rsplit("/", 1)[0] not in directories:
            raise BranchError("branch-parent-missing")
        logging = _logging(session.git_dir, target, before.config)
        session.logging = logging
        session.check_original()
        self._expected(session.snapshot(), expected_revision)
        return BranchCreatePlan(name, expected_reference_revision, self._key, before, logging)

    @core._session_boundary
    def prepare_branch(self, name, *, expected_revision, expected_reference_revision) -> BranchReview:
        core._need(not self._retained and not self._apply_entered, "recovery-required")
        plan = self._capture(self._session(), name, expected_revision, expected_reference_revision)
        return BranchReview(plan, _review_digest(plan))

    @core._session_boundary
    def apply_branch(self, review: BranchReview, owner: core.MutationOwner, *, expected_digest: str) -> core.MutationResult:
        core._need(type(review) is BranchReview and type(review.plan) is BranchCreatePlan
                   and review.plan._key is self._key and not review.plan._used and not self._apply_entered,
                   "already-used")
        core._need(type(expected_digest) is str and review.digest == expected_digest == _review_digest(review.plan),
                   "stale-observation")
        core._need(not self._retained, "recovery-required")
        self._apply_entered = True  # Before any original-owner callback/reentry.
        plan = review.plan
        handoff = _BranchHandoff(self, plan, owner)
        self._active_plan, self._active_owner = plan, handoff
        transaction = None
        intent = observation = reason = None
        state, settlement = "failed", "settled"
        try:
            handoff.check_current(self.root, plan.action, plan._snapshot.public.revision)
            session = self._session()
            current = self._capture(session, plan.name, plan._snapshot.public.revision, plan.reference_revision)
            core._need(_review_digest(current) == review.digest, "stale-observation")
            plan._used = True
            transaction = self._transaction = _BranchTransaction(session, current._snapshot, plan, handoff)
            transaction.acquire()
            head = plan._snapshot.public.head
            core._need(head is not None, "authorization")
            intent = BranchIntent(plan._snapshot.public.revision, plan.reference_revision, plan._snapshot.public.branch,
                                  head, plan._snapshot.index_stamp.digest, plan.target, head)
            transaction.check_original()
            handoff.record_intent(intent)
            transaction.check_original()
            transaction.release_head_lock()
            transaction.check_original()
            session.git(["update-ref", "--no-deref", "-m", _MESSAGE, plan.target, head, "0" * len(head)], limit=1024)
            transaction.accept_publication()
            state = "succeeded"
        except ProcessError as error:
            if error.fatal:
                self._unknown = True
                state, settlement, reason = "unknown", "unknown", "unknown"
            else:
                state, reason = ("recovery-required", "recovery-required") if intent is not None else ("failed", "command-failed")
        except (core.GitError, OSError) as error:
            state = "recovery-required" if intent is not None else "failed"
            reason = error.reason if isinstance(error, core.GitError) else "command-failed"
        except BaseException:
            self._unknown = True
            if transaction is not None:
                transaction.retained = True
                self._retained.append(transaction)
            raise
        try:
            if transaction is not None:
                if self._unknown:
                    transaction.retained = True
                    self._retained.append(transaction)
                else:
                    closed = transaction.close()
                    if not closed:
                        transaction.retained = True
                        self._retained.append(transaction)
                        state, reason = "recovery-required", "recovery-required"
                    if transaction.uncertain_closes or transaction.config_lock.unknown:
                        self._unknown = True
                    if self._unknown:
                        state, settlement, reason = "unknown", "unknown", "unknown"
                    elif state == "succeeded":
                        try:
                            observation = session.snapshot().public
                        except ProcessError as error:
                            if error.fatal:
                                self._unknown = True
                                state, settlement, reason = "unknown", "unknown", "unknown"
                                transaction.retained = True
                                self._retained.append(transaction)
                            else:
                                state, reason = "recovery-required", "recovery-required"
                        except (core.GitError, OSError):
                            state, reason = "recovery-required", "recovery-required"
        except BaseException:
            self._unknown = True
            if transaction is not None and transaction not in self._retained:
                transaction.retained = True
                self._retained.append(transaction)
            raise
        finally:
            if not self._unknown:
                self._active_plan = self._active_owner = None
        return core.MutationResult(handoff.operation_id, plan.action, state, settlement, reason, observation, intent)

    def _refuse_other_write(self, *args, **kwargs):
        raise core.GitError("invalid-input")

    prepare_local = prepare_stage = prepare_unstage = prepare_commit = apply_review = apply = reconcile = _refuse_other_write
