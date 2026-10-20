"""One reviewed, ordinary push to the current branch's existing upstream.

The existing GitLocal/GitRemote native owners provide the actual source, selected
Connection, private command channel and journal. These closed core comparisons
never issue credentials, construct a native receipt or authorize arbitrary Git.
Only committed objects are sent; index/worktree/ref/config contents are not
published here. Initial/new-branch push and upstream configuration are separate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re

from . import git_repository_local as local
from . import git_repository_read as read
from . import git_service as core
from .git_push_transport import Target
from .git_push_wire import Selection
from .owned_process import ProcessError


MAX_COMMITS = 64
MAX_TREES_BYTES = 32 * 1024 * 1024  # Aggregate inspected output, never retained as one buffer.
_REMOTE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z", re.ASCII)
_OID = re.compile(r"[a-f0-9]{40}\Z", re.ASCII)
_REASONS = frozenset({"push-upstream", "push-history", "push-policy", "push-output",
                      "push-target-changed", "push-remote-refused"})


class PushError(core.GitError):
    def __init__(self, reason):
        core._need(reason in _REASONS, "invalid-input")
        super().__init__("invalid-input")
        self.reason = reason


def require(value, reason="push-policy"):
    if not value:
        raise PushError(reason)


def remote_name(value):
    require(type(value) is str and _REMOTE.fullmatch(value) is not None, "push-upstream")
    core._need(core._SECRET.search(value.encode("ascii")) is None, "sensitive-content")
    return value


def tracking_ref(remote, selected):
    core._need(type(selected) is Selection, "invalid-input")
    return "refs/remotes/" + remote_name(remote) + "/" + selected.remote_ref[len("refs/heads/"):]


def _configuration(config, remote, target):
    """Read actual policy; never copy an original executable/network setting."""
    core._need(type(target) is Target, "invalid-input")
    selected = target.selected
    remote_name(remote)
    branch = "branch." + selected.local_ref[len("refs/heads/"):] + "."
    prefix = "remote." + remote + "."
    url = ("https://github.com/" + target.repository + ".git").encode("ascii")
    require(config.get(branch + "remote") == (remote.encode("ascii"),)
            and config.get(branch + "merge") == (selected.remote_ref.encode("ascii"),), "push-upstream")
    require(branch + "pushremote" not in config and "remote.pushdefault" not in config, "push-upstream")
    require(config.get(prefix + "url") == (url,), "push-upstream")
    wildcard = ("+refs/heads/*:refs/remotes/" + remote + "/*").encode("ascii")
    exact = ("+" + selected.remote_ref + ":" + tracking_ref(remote, selected)).encode("ascii")
    require(config.get(prefix + "fetch") in ((wildcard,), (wildcard[1:],), (exact,), (exact[1:],)), "push-upstream")
    allowed = {prefix + "url", prefix + "fetch", prefix + "pushurl", prefix + "tagopt"}
    fixed = {"push.default": ((b"simple",), (b"upstream",), (b"current",)),
             "push.followtags": ((b"false",),), "push.gpgsign": ((b"false",),),
             "push.recursesubmodules": ((b"no",),), "push.negotiate": ((b"false",),),
             "push.useforceifincludes": ((b"false",),)}
    for key, values in config.items():
        require(not key.startswith(("url.", "http.", "credential.", "protocol.", "core.ssh", "lfs.",
                                    "submodule.", "fetch.")))
        require(key not in ("core.gitproxy", "core.askpass", "core.alternaterefscommand"))
        if key.startswith("push."):
            require(key in fixed and values in fixed[key])
        if key.startswith(prefix):
            require(key in allowed)
            if key == prefix + "pushurl":
                require(values == (url,))
            elif key == prefix + "tagopt":
                require(values == (b"--no-tags",))
    require(config.get("extensions.objectformat", (b"sha1",)) == (b"sha1",)
            and config.get("core.repositoryformatversion", (b"0",)) == (b"0",))


@dataclass(slots=True, repr=False)
class PushPlan:
    remote: str
    target: Target
    reference_revision: str
    commits: tuple[str, ...]
    _trees: tuple[str, ...]
    _hooks: tuple
    _key: object
    _snapshot: core._Snapshot
    _used: bool = False
    action: str = field(default="push", init=False)

    @property
    def paths(self):
        return ()  # Never an implicit stage/commit selection.

    def public(self):
        selected, source = self.target.selected, self._snapshot.public
        return {"action": "push", "remote": self.remote, "repository": self.target.repository,
                "accountId": self.target.account_id, "repositoryId": self.target.repository_id,
                "login": self.target.login, "branch": selected.local_ref, "head": selected.new_oid,
                "upstreamRef": selected.remote_ref, "expectedRemoteOid": selected.old_oid,
                "trackingRef": tracking_ref(self.remote, selected), "commits": list(self.commits),
                "expectedRevision": source.revision, "expectedReferenceRevision": self.reference_revision,
                "expectedIndex": self._snapshot.index_stamp.digest, "basis": "existing-configured-upstream",
                "withheld": ["messages", "authors", "emails", "signatures", "objects"]}


def _review_digest(plan):
    core._need(type(plan) is PushPlan, "invalid-input")
    raw = json.dumps({"review": plan.public(), "trees": plan._trees, "hooks": plan._hooks},
                     sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(b"mrk-git-push-review/1\0" + raw).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class PushReview:
    plan: PushPlan
    digest: str

    def as_dict(self):
        return {**self.plan.public(), "reviewDigest": self.digest}


@dataclass(frozen=True, slots=True, repr=False)
class PushIntent:
    """Candidate fence before pack send; body digest is added only after EOF.

    This DATA is insufficient to send. The SAME original channel must receive
    the original durable ACK and consume it exactly once at helper-send.
    """
    review_digest: str
    expected_revision: str
    expected_reference_revision: str
    expected_index: str
    remote: str
    repository: str
    account_id: str
    repository_id: str
    local_ref: str
    remote_ref: str
    old_oid: str
    new_oid: str
    commits_sha256: str
    action: str = field(default="push", init=False)

    @classmethod
    def from_plan(cls, plan, digest):
        core._need(type(plan) is PushPlan and digest == _review_digest(plan), "authorization")
        selected, target = plan.target.selected, plan.target
        commits = b"".join((oid + "\n").encode("ascii") for oid in plan.commits)
        return cls(digest, plan._snapshot.public.revision, plan.reference_revision,
                   plan._snapshot.index_stamp.digest, plan.remote, target.repository, target.account_id,
                   target.repository_id, selected.local_ref, selected.remote_ref, selected.old_oid,
                   selected.new_oid, hashlib.sha256(commits).hexdigest())

    def as_dict(self):
        return {"action": self.action, "reviewDigest": self.review_digest,
                "expectedRevision": self.expected_revision, "expectedReferenceRevision": self.expected_reference_revision,
                "expectedIndex": self.expected_index, "remote": self.remote, "repository": self.repository,
                "accountId": self.account_id, "repositoryId": self.repository_id,
                "localRef": self.local_ref, "remoteRef": self.remote_ref,
                "oldOid": self.old_oid, "newOid": self.new_oid, "commitsSha256": self.commits_sha256}


class _Session(local._LocalSession):
    def __init__(self, repository):
        super().__init__(repository)
        self.push_selection = None
        self.push_tree = None
        self.push_tracking = None

    def _hooks(self):
        result = super()._hooks()
        if result == (("hooks", None),):
            return result
        try:
            original = core._identity((self.git_dir / "hooks/pre-push").lstat())
        except FileNotFoundError:
            original = None
        return (*result, ("hooks/pre-push", original))

    def restrictions(self, config):
        reasons = set(super().restrictions(config))
        # Do not override an installed repository hook with the fixed ACK hook.
        # Non-executable files are conservatively refused too, never deleted.
        if dict(self._hooks()).get("hooks/pre-push") is not None:
            reasons.add("required-hooks")
        return tuple(sorted(reasons))

    def _extra_arguments(self, args, index, identity):
        selected = self.push_selection
        if index is not None or identity is not None:
            return False
        if self.push_tracking is not None and args == ["symbolic-ref", "--quiet", self.push_tracking]:
            return True
        if selected is None:
            return False
        if args == ["rev-list", "--reverse", "--topo-order", "--max-count=" + str(MAX_COMMITS + 1),
                    selected.old_oid + ".." + selected.new_oid, "--"]:
            return True
        return self.push_tree is not None and args == ["ls-tree", "-r", "-z", "--full-tree", self.push_tree]

    def outgoing(self, selected, ahead):
        core._need(type(selected) is Selection and self.push_selection is None, "invalid-input")
        self.push_selection = selected
        _, raw = self.git(["rev-list", "--reverse", "--topo-order", "--max-count=" + str(MAX_COMMITS + 1),
                           selected.old_oid + ".." + selected.new_oid, "--"], limit=(MAX_COMMITS + 1) * 41)
        require(raw.endswith(b"\n") and b"\r" not in raw, "push-history")
        try:
            commits = tuple(raw[:-1].decode("ascii").split("\n"))
        except UnicodeError:
            raise PushError("push-history") from None
        require(1 <= len(commits) <= MAX_COMMITS and len(commits) == ahead
                and len(set(commits)) == len(commits) and commits[-1] == selected.new_oid
                and selected.old_oid not in commits
                and all(_OID.fullmatch(oid) is not None and oid != "0" * 40 for oid in commits), "push-history")
        trees, total = [], 0
        for oid in commits:
            self.push_tree = oid
            _, body = self.git(["ls-tree", "-r", "-z", "--full-tree", oid])
            total += len(body)
            core._need(total <= MAX_TREES_BYTES, "limit")
            seen = set()
            for row in core._nul(body):
                header, tab, path = row.partition(b"\t")
                parts = header.split(b" ")
                require(tab == b"\t" and len(parts) == 3 and parts[0] in (b"100644", b"100755", b"120000")
                        and parts[1] == b"blob" and _OID.fullmatch(core._oid(parts[2])) is not None
                        and parts[2] != b"0" * 40)
                name = core._decode_path(path)
                require(name not in seen and len(name.split("/")) <= read.MAX_REF_DEPTH
                        and name.split("/")[-1] not in (".gitmodules", ".gitattributes", ".lfsconfig"))
                # No key/credential payload is deliberately selected by this
                # first slice. This is a path refusal, NOT a secret scanner.
                core._need(not core._sensitive_path(name), "sensitive-content")
                seen.add(name)
                core._need(len(seen) <= core.MAX_ENTRIES, "limit")
            trees.append(hashlib.sha256(body).hexdigest())
        self.push_tree = None
        self.check_original(); self.guard_current()
        return commits, tuple(trees)


class GitPushRepository(local.GitLocalRepository):
    """Same core custody with one fixed original private remote-command seam."""
    def __init__(self, root, *, git_executable, work_end, launch, cancellation=None,
                 _run=core.run_owned, _remote=None):
        super().__init__(root, git_executable=git_executable, work_end=work_end, cancellation=cancellation, _run=_run)
        from .git_push_transaction import Launch
        core._need(type(launch) is Launch and launch.context is not None, "authorization")
        self.launch, self._remote = launch, _remote

    def _session(self):
        core._need(not self._unknown, "unknown")
        session = _Session(self)
        self._active_sessions.append(session)
        session.discover()
        return session

    def _capture(self, session, target, revision, reference_revision):
        core._need(type(target) is Target, "invalid-input")
        before = session.snapshot()
        self._expected(before, revision)
        core._need(session.reference_revision(before.public) == reference_revision, "stale-observation")
        self._policy(before, "push")
        core._need("required-signing" not in before.public.restrictions, "required-signing")
        selected = target.selected
        require((before.public.branch, before.public.head) == (selected.local_ref, selected.new_oid), "push-upstream")
        require(not session.originals.shallow, "push-history")
        tracking = session.tracking(before.public)
        require(tracking.state == "complete" and tracking.merge_ref == selected.remote_ref
                and tracking.head == selected.old_oid and tracking.behind == 0
                and type(tracking.ahead) is int and 1 <= tracking.ahead <= MAX_COMMITS, "push-history")
        require(tracking.local_ref == tracking_ref(tracking.remote, selected), "push-upstream")
        # A symbolic cached alias is not the configured branch tip.
        session.push_tracking = tracking.local_ref
        code, _ = session.git(["symbolic-ref", "--quiet", tracking.local_ref], accept=(0, 1), limit=2048)
        require(code == 1, "push-upstream")
        _configuration(before.config, tracking.remote, target)
        commits, trees = session.outgoing(selected, tracking.ahead)
        self._expected(session.snapshot(), revision)
        core._need(session.reference_revision(before.public) == reference_revision, "stale-observation")
        session.check_original(); session.guard_current()
        return PushPlan(tracking.remote, target, reference_revision, commits, trees, session.hooks,
                        self._key, before)

    @core._session_boundary
    def prepare_push(self, target, *, expected_revision, expected_reference_revision):
        from .git_push_transaction import PushTransaction
        core._need(not self._retained and not self._apply_entered and callable(self._remote), "authorization")
        session = self._session()
        plan = self._capture(session, target, expected_revision, expected_reference_revision)
        tx = self._transaction = PushTransaction(session, plan._snapshot, plan, None, _review_digest(plan), "review")
        primary = None
        try:
            tx.prepare_view()
            tx.run()
        except BaseException as error:
            self._unknown |= (isinstance(error, ProcessError) and error.fatal
                              or not isinstance(error, (core.GitError, ProcessError, OSError)))
            primary = error
        try:
            if self._unknown or not tx.close(preserve_scratch=primary is not None):
                self._unknown |= tx.unknown
                tx.retained = True
                self._retained.append(tx)
            # A known process/descriptor close can still leave the exact
            # unsuccessful private view retained. That is not a fresh-review
            # permission or evidence that the private output was settled.
            if tx.retained and tx not in self._retained:
                self._retained.append(tx)
        except BaseException:
            self._unknown = tx.retained = True
            if tx not in self._retained:
                self._retained.append(tx)
            if primary is None:
                raise
        if primary is not None:
            raise primary
        core._need(not self._unknown and tx.complete, "unknown")
        session.check_original(); session.guard_current()
        return PushReview(plan, _review_digest(plan))

    @core._session_boundary
    def prepare_push_apply(self, target, *, expected_revision, expected_reference_revision, expected_digest):
        """Fresh local comparisons for the native-held, previously reviewed Apply.

        This never repeats the prior dry-run/helper or grants Apply from a
        serialized review. The native original still owns that review and its
        explicit consent; its fixed request binds this digest before GO.
        """
        core._need(not self._retained and not self._apply_entered and callable(self._remote), "authorization")
        session = self._session()
        plan = self._capture(session, target, expected_revision, expected_reference_revision)
        digest = _review_digest(plan)
        core._need(digest == expected_digest, "stale-observation")
        return PushReview(plan, digest)

    @core._session_boundary
    def apply_push(self, review, owner, *, expected_digest):
        from .git_push_transaction import PushTransaction
        core._need(type(review) is PushReview and type(review.plan) is PushPlan and review.plan._key is self._key
                   and not review.plan._used and not self._apply_entered and not self._retained, "already-used")
        core._need(review.digest == expected_digest == _review_digest(review.plan), "stale-observation")
        self._apply_entered = True
        plan = review.plan
        self._active_plan, self._active_owner = plan, owner
        state, settlement, reason, tx = "failed", "settled", None, None
        try:
            owner.check_current(self.root, "push", plan._snapshot.public.revision)
            session = self._session()
            current = self._capture(session, plan.target, plan._snapshot.public.revision, plan.reference_revision)
            core._need(_review_digest(current) == review.digest, "stale-observation")
            plan._used = True
            tx = self._transaction = PushTransaction(session, current._snapshot, plan, owner, review.digest, "apply")
            tx.acquire()
            tx.run()
            state = "succeeded"
        except ProcessError as error:
            if error.fatal:
                self._unknown = True
                state, settlement, reason = "unknown", "unknown", "unknown"
            else:
                state, reason = ("recovery-required", "recovery-required") if tx and tx.intent else ("failed", "command-failed")
        except (core.GitError, OSError) as error:
            state = "recovery-required" if tx and tx.intent else "failed"
            reason = error.reason if isinstance(error, core.GitError) else "command-failed"
        except BaseException:
            self._unknown = True
            if tx is not None:
                tx.retained = True; self._retained.append(tx)
            raise
        try:
            if tx is not None:
                if self._unknown:
                    tx.retained = True; self._retained.append(tx)
                elif not tx.close(preserve_scratch=state != "succeeded"):
                    state, reason = "recovery-required", "recovery-required"
                if tx.retained and tx not in self._retained:
                    self._retained.append(tx)
                    if state == "failed":
                        state = "recovery-required"
                if tx.unknown or tx.uncertain_closes or tx.config_lock.unknown:
                    self._unknown = True
                    state, settlement, reason = "unknown", "unknown", "unknown"
        except BaseException:
            self._unknown = True
            if tx is not None and tx not in self._retained:
                tx.retained = True; self._retained.append(tx)
            raise
        finally:
            if not self._unknown:
                self._active_plan = self._active_owner = None
        return core.MutationResult(core._text(owner.operation_id, 128), "push", state, settlement, reason, None,
                                   None if tx is None else tx.intent)

    def _refuse_other_write(self, *args, **kwargs):
        raise core.GitError("invalid-input")

    prepare_local = prepare_stage = prepare_unstage = prepare_commit = apply_review = apply = reconcile = _refuse_other_write
