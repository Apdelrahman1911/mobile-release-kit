"""Content-only local FF over the original GitLocal/Switch owners.

Only the configured, already-fetched tracking tip is selectable. This module
does not fetch, merge, reset, admit a native operation, or own a journal.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path

from . import git_repository_local as local
from . import git_repository_read as read
from . import git_repository_switch as switch
from . import git_service as core
from .owned_process import ProcessError

KIND = "fast-forward"
MESSAGE = "MRK: fast-forward to reviewed cached tracking commit"
REASONS = frozenset(("ff-target", "ff-not-descendant", "ff-layout", "ff-log-limit"))


class FastForwardError(core.GitError):
    def __init__(self, reason):
        core._need(reason in REASONS, "invalid-input")
        super().__init__("invalid-input")
        self.reason = reason


def require(value, reason):
    if not value:
        raise FastForwardError(reason)


def tracking_ref(value):
    return (type(value) is str and value.startswith("refs/remotes/") and read._full_ref(value)
            and 4 <= len(value.split("/")) <= read.MAX_REF_DEPTH
            and value.rsplit("/", 1)[-1] != "HEAD"
            and core._SECRET.search(value.encode("utf-8")) is None)


def _branch_logging(session, before, head_log):
    path = session.git_dir / "logs" / before.public.branch
    # Only existing private ancestry; never manufacture a log parent.
    current = session.git_dir
    parents = []
    for name in path.relative_to(current).parts[:-1]:
        current /= name
        parents.append((str(current.relative_to(session.git_dir)), switch._directory(current)))
    stamp, content = core._read(path, switch.MAX_LOG)
    require(stamp.kind in ("absent", "file"), "ff-layout")
    require(stamp.kind != "file" or (len(content) <= switch.MAX_LOG and (not content or content.endswith(b"\n"))),
            "ff-log-limit")
    enabled = before.config.get("core.logallrefupdates", (b"true",)) == (b"true",) or stamp.kind == "file"
    rosters = tuple((name, tuple(sorted(session.names(session.git_dir / name)))) for name, _ in parents)
    return switch._Log(enabled, stamp, content, parents[-1][1], head_log.identity), tuple(parents), rosters


@dataclass(slots=True, repr=False)
class FastForwardPlan:
    target_ref: str
    target_oid: str
    reference_revision: str
    source_tree: tuple
    target_tree: tuple
    changed: tuple
    _key: object
    _snapshot: core._Snapshot
    _footprint: switch._Footprint
    _log: switch._Log
    _branch_log: switch._Log
    _log_parents: tuple
    _log_rosters: tuple
    _target_hashes: tuple
    _used: bool = False
    action: str = field(default=KIND, init=False)

    @property
    def target(self):
        return self.target_ref

    def public(self):
        original = self._snapshot
        log = lambda p: {"enabled": p.enabled, "originalKind": p.original.kind,
                         "originalSha256": p.original.digest}
        source = dict(self._footprint.files)
        targets = dict(self._target_hashes)
        after = {v.path: v for v in self.target_tree}
        return {"action": KIND, "targetRef": self.target_ref, "targetOid": self.target_oid,
                "expectedRevision": original.public.revision, "expectedReferenceRevision": self.reference_revision,
                "head": original.public.head, "branch": original.public.branch,
                "expectedIndex": original.index_stamp.digest, "paths": list(self.changed),
                "trackedCount": len(self.source_tree), "contentOnly": True, "basis": "local-refs-no-fetch",
                "files": [{"path": f.path, "mode": f.mode, "sourceOid": f.oid, "targetOid": after[f.path].oid,
                           "sourceSha256": source[f.path].digest, "targetSha256": targets[f.path],
                           "targetSize": after[f.path].size} for f in self.source_tree if f.path in self.changed],
                "headLog": log(self._log), "branchLog": log(self._branch_log)}


def review_digest(plan):
    return switch._hash({"domain": "mrk-git-fast-forward-review/1", "review": plan.public(),
        "source": [(f.path, f.mode, f.oid, f.size) for f in plan.source_tree],
        "target": [(f.path, f.mode, f.oid, f.size) for f in plan.target_tree],
        "footprint": plan._footprint.comparison(), "headLog": plan._log.comparison(),
        "branchLog": plan._branch_log.comparison(), "parents": plan._log_parents, "logNames": plan._log_rosters,
        "metadata": [(str(p), s.kind, s.identity, s.digest) for p, s in sorted(plan._snapshot.metadata.items())]})


@dataclass(frozen=True, slots=True, repr=False)
class FastForwardReview:
    plan: FastForwardPlan
    digest: str

    def as_dict(self):
        return {**self.plan.public(), "reviewDigest": self.digest}


@dataclass(frozen=True, slots=True, repr=False)
class FastForwardIntent:
    expected_revision: str
    expected_reference_revision: str
    expected_ref: str
    expected_head: str
    expected_index: str
    target_ref: str
    target_oid: str
    candidate_index: str
    original_head: str
    original_head_log: str
    original_branch_log: str
    head_log_enabled: bool
    branch_log_enabled: bool
    footprint: str
    action: str = field(default=KIND, init=False)

    def as_dict(self):
        names = ("expectedRevision", "expectedReferenceRevision", "expectedRef", "expectedHead", "expectedIndex",
                 "targetRef", "targetOid", "candidateIndex", "originalHead", "originalHeadLog", "originalBranchLog",
                 "headLogEnabled", "branchLogEnabled", "footprint")
        return {"action": KIND, **dict(zip(names, (getattr(self, f) for f in self.__dataclass_fields__ if f != "action")))}


class _FastForwardSession(switch._SwitchSession):
    def guard_current(self):
        local._LocalSession.guard_current(self)

    def check_original(self):
        current = read._inventory(self.git_dir, self.checkpoint, self.names)
        expected = self.originals
        if self.target_lock is not None:
            self.target_lock.check()
            expected, current = self.target_lock.comparison(expected), self.target_lock.comparison(current)
        core._need(local._inventory_matches(expected, current, objects_written=False, successor=self.successor),
                   "stale-observation")
        hooks = self._hooks()
        if self.hooks is None:
            self.hooks = hooks
        core._need(hooks == self.hooks, "stale-observation")
        self.check_object_parents()

    def command_spec(self, args, *, index=None, identity=None):
        if args and args[0] == "update-ref":
            transaction = self.repository._transaction
            core._need(transaction is not None and transaction.session is self
                       and self.execution_command == (tuple(args), index, identity)
                       and identity is transaction.plan._log.identity and index is None, "authorization")
            transaction.check_original()
            seed = ["ls-files", "--stage", "-z"]
            argv, environment = read._ReadSession.command_spec(self, seed)
            argv[argv.index("--git-dir=" + str(self.frozen.root))] = "--git-dir=" + str(self.git_dir)
            environment.update(GIT_COMMITTER_NAME=identity.name, GIT_COMMITTER_EMAIL=identity.email)
            return [*argv[:-len(seed)], *args], environment
        return super().command_spec(args, index=index, identity=identity)


class GitFastForwardRepository(switch.GitSwitchRepository):
    def _session(self):
        core._need(not self._unknown, "unknown")
        session = _FastForwardSession(self)
        self._active_sessions.append(session)
        session.discover()
        return session

    def _capture_fast_forward(self, session, target_ref, target_oid, expected_revision, expected_reference_revision):
        core._need(tracking_ref(target_ref) and type(target_oid) is str and core._OID.fullmatch(target_oid)
                   and type(expected_reference_revision) is str and core._REVISION.fullmatch(expected_reference_revision),
                   "invalid-input")
        before = session.snapshot()
        self._expected(before, expected_revision)
        core._need(session.reference_revision(before.public) == expected_reference_revision, "stale-observation")
        # Same conservative checkout policy, not merge/rebase behavior.
        self._policy(before, "branch-switch")
        core._need("required-signing" not in before.public.restrictions, "required-signing")
        require(before.public.head is not None and before.public.branch is not None
                and before.index_stamp.kind == "file" and len(before.index_bytes) <= switch.MAX_INDEX, "ff-layout")
        switch._require(not any(r.index not in ("?", "!") or r.worktree not in ("?", "!") for r in before.public.changes),
                        "switch-dirty")
        require(before.config.get("core.autocrlf", (b"false",)) == (b"false",)
                and not any(k.startswith("checkout.") for k in before.config)
                and before.config.get("core.sharedrepository", (b"false",)) in ((b"false",), (b"0",)), "ff-layout")
        for fixed in ("worktrees", "info/sparse-checkout"):
            require(core._read(session.git_dir / fixed, 65536, regular=False)[0].kind == "absent", "ff-layout")
        tracking = session.tracking(before.public)
        require(tracking.state == "complete" and tracking.local_ref == target_ref and tracking.head == target_oid, "ff-target")
        require(tracking.ahead == 0 and 1 <= tracking.behind <= read.MAX_WALK and target_oid != before.public.head,
                "ff-not-descendant")
        # First slice accepts ordinary loose refs only, with actual original
        # parents. Symbolic tracking refs / packed-only refs do not get adopted.
        for reference, oid in ((before.public.branch, before.public.head), (target_ref, target_oid)):
            path = session.git_dir / reference
            current = session.git_dir
            for name in path.relative_to(current).parts[:-1]:
                current /= name
                switch._directory(current)
            stamp, raw = core._read(path, 65)
            require(stamp.kind == "file" and raw == (oid + "\n").encode("ascii"), "ff-layout")
        source, target, changed, footprint, hashes = switch._content(session, before, target_oid)
        head_log = switch._logging(session.git_dir, before.config)
        branch_log, parents, rosters = _branch_logging(session, before, head_log)
        plan = FastForwardPlan(target_ref, target_oid, expected_reference_revision, source, target, changed,
            self._key, before, footprint, head_log, branch_log, parents, rosters, hashes)
        session.switch_plan = plan
        session.check_original()
        session._check_frozen()
        core._need(all(core._read(p, 65536)[0] == s for p, s in before.metadata.items()), "stale-observation")
        return plan

    @core._session_boundary
    def prepare_fast_forward(self, target_ref, target_oid, *, expected_revision, expected_reference_revision):
        core._need(not self._retained and not self._apply_entered, "recovery-required")
        plan = self._capture_fast_forward(self._session(), target_ref, target_oid, expected_revision, expected_reference_revision)
        return FastForwardReview(plan, review_digest(plan))

    @core._session_boundary
    def apply_fast_forward(self, review, owner, *, expected_digest):
        core._need(type(review) is FastForwardReview and type(review.plan) is FastForwardPlan and review.plan._key is self._key
                   and not review.plan._used and not self._apply_entered and not self._retained, "already-used")
        core._need(review.digest == expected_digest == review_digest(review.plan), "stale-observation")
        self._apply_entered = True
        session = self._session()
        plan = self._capture_fast_forward(session, review.plan.target_ref, review.plan.target_oid,
            review.plan._snapshot.public.revision, review.plan.reference_revision)
        core._need(review_digest(plan) == review.digest, "stale-observation")
        review.plan._used = True
        return self._apply_captured(session, FastForwardReview(plan, review.digest), owner)

    def _apply_captured(self, session, review, owner):
        from .git_fast_forward_transaction import BorrowedTrackingLock, FastForwardTransaction, Handoff, TrackingLock
        core._need(self._apply_entered and self._active_sessions == [session] and type(session) is _FastForwardSession
                   and session.repository is self and self._transaction is None and type(review) is FastForwardReview
                   and review.plan._key is self._key and review.digest == review_digest(review.plan), "authorization")
        plan = review.plan
        handoff = Handoff(self, plan, owner)
        self._active_plan, self._active_owner = plan, handoff
        transaction = intent = observation = reason = None
        state, settlement = "failed", "settled"
        try:
            session.guard_current()
            if self._target_lock is None:
                self._target_lock = session.target_lock = TrackingLock(self.root, plan.target_ref)
                self._target_lock.acquire()
            else:
                core._need(type(self._target_lock) is BorrowedTrackingLock and self._target_lock.target == plan.target_ref,
                           "authorization")
                self._target_lock.check()
            session.originals = self._target_lock.comparison(session.originals)
            transaction = self._transaction = FastForwardTransaction(session, plan._snapshot, plan, handoff)
            transaction.acquire()
            transaction.prepare_candidates()
            intent = transaction.intent
            handoff.record_intent(intent)
            transaction.checkout()
            transaction.publish_index()
            transaction.publish_ref()
            state = "succeeded"
        except ProcessError as error:
            if error.fatal:
                self._unknown = True
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
                if self._unknown or not transaction.close(preserve_scratch=intent is not None and state != "succeeded"):
                    transaction.retained = True
                    state, reason = "recovery-required", "recovery-required"
                if transaction.retained:
                    self._retained.append(transaction)
                if transaction.uncertain_closes or transaction.directory_closes or transaction.config_lock.unknown:
                    self._unknown = True
                if not self._unknown and state == "succeeded":
                    observation = session.snapshot().public
        except BaseException:
            self._unknown = True
            if transaction is not None and transaction not in self._retained:
                self._retained.append(transaction)
            raise
        if self._unknown:
            state, settlement, reason = "unknown", "unknown", "unknown"
        else:
            self._active_plan = self._active_owner = None
        return core.MutationResult(handoff.operation_id, KIND, state, settlement, reason, observation, intent)

    def _finish_sessions(self, uncertain):
        from .git_fast_forward_transaction import TrackingLock
        good = local.GitLocalRepository._finish_sessions(self, uncertain)
        if good and type(self._target_lock) is TrackingLock:
            try:
                good = self._target_lock.close()
            except BaseException:
                self._unknown = True
                raise
            self._unknown |= not good
        return good

    prepare_local = apply_review = prepare_branch = apply_branch = prepare_switch = apply_switch = switch.GitSwitchRepository._refuse_other_write
