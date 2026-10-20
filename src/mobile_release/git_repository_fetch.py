"""One reviewed GitHub branch -> one local remote-tracking ref.

The original GitRemote input supplies credential/channel admission and the SAME
GitLocal publisher, journal and native source owners. This core never obtains
credentials, connects a socket, grants a request or infers process settlement.
All negotiation/object validation is stock Git in an isolated empty object
store. Original object publication is impossible before its candidate ACK and
an actual native-held keep marker. Required repository policies are refused,
not executed or silently overridden.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time

from . import git_repository_branches as branches
from . import git_repository_local as local
from . import git_repository_read as read
from . import git_service as core
from .git_remote_transport import Target
from .git_remote_wire import Selection
from .owned_process import ProcessError

MAX_LOG = 128 * 1024
PRIVATE_REF = "refs/heads/mrk-fetch"
REF_MESSAGE = "MRK: fetch reviewed remote branch"
_FETCH_REASONS = frozenset(("fetch-remote", "fetch-layout", "fetch-identity-required",
    "fetch-ref-parent", "fetch-output", "fetch-object-limit", "fetch-target-changed", "fetch-up-to-date"))
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z", re.ASCII)
_OID = re.compile(r"[a-f0-9]{40}\Z", re.ASCII)


class FetchError(core.GitError):
    def __init__(self, reason: str):
        core._need(reason in _FETCH_REASONS, "invalid-input")
        super().__init__("invalid-input")
        self.reason = reason


def require(value: bool, reason: str = "fetch-layout") -> None:
    if not value:
        raise FetchError(reason)


def remote_name(value) -> str:
    require(type(value) is str and _NAME.fullmatch(value) is not None, "fetch-remote")
    core._need(core._SECRET.search(value.encode("ascii")) is None, "sensitive-content")
    return value


def selected_branch(value) -> str:
    # Ref grammar is shared with the accepted wire firewall; never a refspec,
    # option or arbitrary Git expression. A remote-tracking destination is
    # derived from this exact selection, not supplied separately by a caller.
    selected = Selection(value, None)
    require(len(selected.reference.encode("utf-8")) <= 512
            and len(selected.reference.split("/")) <= read.MAX_REF_DEPTH, "fetch-remote")
    core._need(core._SECRET.search(value.encode("utf-8")) is None, "sensitive-content")
    return selected.reference


def target_ref(remote: str, reference: str) -> str:
    return "refs/remotes/" + remote_name(remote) + "/" + selected_branch(reference)[len("refs/heads/"):]


def _directory(path: Path) -> tuple[int, ...]:
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and not info.st_mode & 0o7022)
    return (*core._identity(info), info.st_uid, info.st_gid)


def _configuration(config: dict, remote: str, selected: Target) -> None:
    require(type(selected) is Target, "fetch-remote")
    name, reference = remote_name(remote), selected_branch(selected.selected.reference)
    prefix = "remote." + name + "."
    expected_url = ("https://github.com/" + selected.repository + ".git").encode("ascii")
    require(config.get(prefix + "url") == (expected_url,), "fetch-remote")
    mapping = config.get(prefix + "fetch")
    wildcard = ("+refs/heads/*:refs/remotes/" + name + "/*").encode("ascii")
    exact = ("+" + reference + ":" + target_ref(name, reference)).encode("utf-8")
    # The configuration '+' expresses ordinary remote-tracking fetch semantics,
    # never force-push. Publication below is still a single expected-old CAS.
    require(mapping in ((wildcard,), (wildcard[1:],), (exact,), (exact[1:],)), "fetch-remote")
    allowed = {prefix + "url", prefix + "fetch", prefix + "pushurl", prefix + "tagopt"}
    for key, values in config.items():
        require(not key.startswith(("url.", "http.", "credential.", "protocol.", "core.ssh", "lfs.", "submodule.", "fetch.")),
                "fetch-remote")
        require(key not in ("core.gitproxy", "core.askpass", "core.alternaterefscommand"), "fetch-remote")
        if key.startswith(prefix):
            require(key in allowed, "fetch-remote")
            if key == prefix + "pushurl":
                require(values == (expected_url,), "fetch-remote")
            elif key == prefix + "tagopt":
                require(values == (b"--no-tags",), "fetch-remote")
    require(config.get("extensions.objectformat", (b"sha1",)) == (b"sha1",))
    require(config.get("core.repositoryformatversion", (b"0",)) == (b"0",))


@dataclass(frozen=True, slots=True, repr=False)
class _Log:
    path: Path
    original: core._Stamp
    content: bytes
    parents: tuple[tuple[Path, tuple[int, ...]], ...]
    enabled: bool
    identity: core.CommitIdentity

    def comparison(self):
        return (self.original.kind, self.original.identity, self.original.digest,
                tuple((str(path), identity) for path, identity in self.parents),
                self.enabled, self.identity.name, self.identity.email)


def _logging(session, target: str) -> _Log:
    config, git = session.config, session.git_dir
    policy = config.get("core.logallrefupdates", (b"true",))
    require(policy in ((b"true",), (b"false",)))
    validator = getattr(branches, "_local_identity", None)
    core._need(validator is not None, "authorization")
    try:
        identity = validator(config)
    except branches.BranchError:
        raise FetchError("fetch-identity-required") from None
    path = git / "logs" / target
    parents = []
    for parent in reversed(path.parents):
        if parent == git or not parent.is_relative_to(git):
            continue
        try:
            parents.append((parent, _directory(parent)))
        except FileNotFoundError:
            # No silent reflog disable and no implicit original directory
            # creation in this first slice. Existing cloned remotes work;
            # missing namespaces need one ordinary Git fetch outside MRK.
            if policy == (b"true",):
                raise FetchError("fetch-ref-parent") from None
            return _Log(path, core._ABSENT, b"", tuple(parents), False, identity)
    original, body = core._read(path, MAX_LOG)
    require(original.kind in ("file", "absent") and (not body or body.endswith(b"\n")))
    if original.kind == "file":
        info = path.lstat()
        require(core._identity(info) == original.identity and stat.S_ISREG(info.st_mode)
                and info.st_uid == os.getuid() and info.st_nlink == 1 and not info.st_mode & 0o7022)
    return _Log(path, original, body, tuple(parents), policy == (b"true",) or original.kind == "file", identity)


@dataclass(slots=True, repr=False)
class FetchPlan:
    remote: str
    target: Target
    reference_revision: str
    expected_target: str | None
    _key: object
    _snapshot: core._Snapshot
    _logging: _Log
    _used: bool = False
    action: str = field(default="fetch", init=False)

    @property
    def target_ref(self):
        return target_ref(self.remote, self.target.selected.reference)

    @property
    def paths(self):
        return ()

    def public(self):
        source = self._snapshot.public
        return {"action": "fetch", "remote": self.remote, "repository": self.target.repository,
                "reference": self.target.selected.reference, "targetRef": self.target_ref,
                "expectedTarget": self.expected_target, "candidateRefOid": self.target.selected.oid,
                "expectedRevision": source.revision, "expectedReferenceRevision": self.reference_revision,
                "head": source.head, "branch": source.branch, "expectedIndex": self._snapshot.index_stamp.digest,
                "accountId": self.target.account_id, "repositoryId": self.target.repository_id,
                "login": self.target.login}


def _review_digest(plan: FetchPlan) -> str:
    value = {"review": plan.public(), "logging": plan._logging.comparison()}
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(b"mrk-git-fetch-review/1\0" + raw).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class FetchReview:
    plan: FetchPlan
    digest: str

    def as_dict(self):
        return {**self.plan.public(), "reviewDigest": self.digest}


@dataclass(frozen=True, slots=True, repr=False)
class FetchIntent:
    review_digest: str
    expected_revision: str
    expected_reference_revision: str
    expected_ref: str | None
    expected_head: str | None
    expected_index: str
    target_ref: str
    expected_target: str | None
    candidate_ref_oid: str
    pack_oid: str
    pack_sha256: str
    pack_bytes: int
    index_sha256: str
    index_bytes: int
    action: str = field(default="fetch", init=False)

    def as_dict(self):
        return {"action": self.action, "reviewDigest": self.review_digest, "expectedRevision": self.expected_revision,
                "expectedReferenceRevision": self.expected_reference_revision, "expectedRef": self.expected_ref,
                "expectedHead": self.expected_head, "expectedIndex": self.expected_index, "targetRef": self.target_ref,
                "expectedTarget": self.expected_target, "candidateRefOid": self.candidate_ref_oid,
                "packOid": self.pack_oid, "packSha256": self.pack_sha256, "packBytes": self.pack_bytes,
                "indexSha256": self.index_sha256, "indexBytes": self.index_bytes}


class _Session(local._LocalSession):
    def __init__(self, repository):
        super().__init__(repository)
        self.fetch_log = None
        self.fetch_log_successor = None
        self.fetch_log_parent = None

    def check_original(self):
        if self.originals is None:
            return super().check_original()
        current = read._inventory(self.git_dir, self.checkpoint, self.names)
        transaction = self.repository._transaction
        if transaction is not None and transaction.session is self:
            current = transaction.normalized_inventory(current)
        core._need(local._inventory_matches(self.originals, current, objects_written=False, successor=self.successor),
                   "stale-observation")
        hooks = self._hooks()
        if self.hooks is None:
            self.hooks = hooks
        core._need(self.hooks == hooks, "stale-observation")
        self.check_object_parents()
        if self.fetch_log is not None:
            self._check_log()

    def _check_log(self, *, published=False):
        log = self.fetch_log
        for path, original in log.parents:
            now = _directory(path)
            if path == log.path.parent and (published or self.fetch_log_parent is not None):
                core._need(now[:3] == original[:3] and now[6:] == original[6:], "stale-observation")
                if self.fetch_log_parent is not None:
                    core._need(now == self.fetch_log_parent, "stale-observation")
            else:
                core._need(now == original, "stale-observation")
        if len(log.parents) != len(tuple(p for p in log.path.parents if p.is_relative_to(self.git_dir) and p != self.git_dir)):
            # Logging was explicitly off and an ancestor absent. It must stay
            # absent, rather than following a new foreign directory/symlink.
            first_missing = (log.parents[-1][0] if log.parents else self.git_dir) / (
                str(log.path.relative_to(self.git_dir)).split("/")[len(log.parents)])
            core._need(core._read(first_missing, 1, regular=False)[0].kind == "absent", "stale-observation")
            return
        stamp, raw = core._read(log.path, MAX_LOG + 2048)
        if not published:
            core._need(stamp == (self.fetch_log_successor or log.original), "stale-observation")
            return
        plan = self.repository._active_plan
        if not log.enabled or plan.expected_target == plan.target.selected.oid:
            core._need(stamp == log.original, "recovery-required")
        else:
            actor = (log.identity.name + " <" + log.identity.email + "> ").encode("utf-8")
            prefix = (plan.expected_target or "0" * 40).encode("ascii") + b" " + plan.target.selected.oid.encode("ascii") + b" " + actor
            core._need(raw.startswith(log.content) and re.fullmatch(re.escape(prefix) + rb"[0-9]{1,12} [+-][0-9]{4}\t"
                       + re.escape(REF_MESSAGE.encode("ascii")) + rb"\n", raw[len(log.content):]) is not None,
                       "recovery-required")
            info = log.path.lstat()
            core._need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                       and not info.st_mode & 0o7022, "recovery-required")
        self.fetch_log_successor, self.fetch_log_parent = stamp, _directory(log.path.parent)

    def remote_tip(self, target: str) -> str | None:
        self.guard_current(); self.check_original(); self._check_frozen()
        args = ["for-each-ref", "--count=257", "--sort=refname", "--format=%(refname)%00%(objectname)%00%(symref)%00",
                "--", "refs/remotes/"]
        _, raw = self.git(args, limit=256 * 1024)
        require(not raw or raw.endswith(b"\n"))
        result, previous, count = None, None, 0
        for line in raw.splitlines():
            fields = line.split(b"\0")
            require(len(fields) == 4 and fields[-1] == b"")
            name = read._decoded(fields[0])
            require(name.startswith("refs/remotes/") and read._full_ref(name)
                    and (previous is None or previous < name))
            count += 1
            core._need(count <= 256, "limit")
            previous = name
            if name != target:
                require(name.casefold() != target.casefold()
                        and not name.casefold().startswith(target.casefold() + "/")
                        and not target.casefold().startswith(name.casefold() + "/"), "fetch-ref-parent")
                continue
            require(fields[2] == b"")  # Never follow/update a symbolic tracking ref.
            result = core._oid(fields[1])
            require(_OID.fullmatch(result) is not None)
        self.check_original(); self.guard_current(); self._check_frozen()
        return result

    def command_spec(self, args, *, index=None, identity=None):
        if args[:1] not in (["for-each-ref"], ["update-ref"]):
            return super().command_spec(args, index=index, identity=identity)
        core._need(index is None and identity is None and self.config is not None and not self.initial_config,
                   "invalid-input")
        plan = self.repository._active_plan
        target = self.repository._selected_target
        core._need(type(target) is str and target.startswith("refs/remotes/") and read._full_ref(target), "invalid-input")
        seed = ["ls-files", "--stage", "-z"]
        argv, env = read._ReadSession.command_spec(self, seed)
        if args[0] == "for-each-ref":
            core._need(args == ["for-each-ref", "--count=257", "--sort=refname", "--format=%(refname)%00%(objectname)%00%(symref)%00",
                               "--", "refs/remotes/"],
                       "invalid-input")
        else:
            tx = self.repository._transaction
            core._need(type(plan) is FetchPlan and tx is not None and tx.session is self and not tx.retained,
                       "authorization")
            tx.publication_ready()
            core._need(args == ["update-ref", "--no-deref", "-m", REF_MESSAGE, target,
                                plan.target.selected.oid, plan.expected_target or "0" * 40], "invalid-input")
            argv[argv.index("--git-dir=" + str(self.frozen.root))] = "--git-dir=" + str(self.git_dir)
            env.update(GIT_COMMITTER_NAME=plan._logging.identity.name, GIT_COMMITTER_EMAIL=plan._logging.identity.email)
        return [*argv[:-len(seed)], *args], env

    def _accept_ref_successor(self):
        # Called only by the original _LocalSession.git positive-return branch.
        plan, tx = self.repository._active_plan, self.repository._transaction
        core._need(type(plan) is FetchPlan and tx is not None and tx.cas_entered and tx.acknowledged
                   and self.successor is None, "recovery-required")
        current = read._inventory(self.git_dir, self.checkpoint, self.names)
        files = {name: (stamp, body) for name, stamp, body in current.files}
        row = files.get(plan.target_ref)
        core._need(row is not None and row[1] == (plan.target.selected.oid + "\n").encode("ascii"), "recovery-required")
        parent = dict(current.directories).get(plan.target_ref.rsplit("/", 1)[0])
        core._need(parent is not None, "recovery-required")
        successor = local._RefSuccessor(plan.target_ref, plan.target.selected.oid, row[0], parent)
        core._need(local._inventory_matches(self.originals, tx.normalized_inventory(current),
                   objects_written=False, successor=successor), "recovery-required")
        tx.sync_ref(plan.target_ref, row[0])
        self._check_log(published=True)
        tx.sync_log(self.fetch_log_successor)
        self.successor = successor
        self.frozen.write(plan.target_ref, row[1])
        self.check_original()
        # Retain this exact positive post-CAS/durability return even if the
        # surrounding original command's final currentness check observes STOP.
        # It can explain a joined recovery outcome, never override that STOP.
        tx.cas_returned, tx.phase = True, "ref-published"


class GitFetchRepository(local.GitLocalRepository):
    """Existing GitLocal core owner with one closed network-command seam.

    ``_run`` remains the original local C/A/W runner. ``_remote`` is ONLY the
    actual fixed worker's one admitted GitRemote command (or an explicit fake
    in passive tests); no public callable/argv authority crosses IPC.
    """
    def __init__(self, root, *, git_executable, work_end, launch, cancellation=None, _run=core.run_owned, _remote=None):
        super().__init__(root, git_executable=git_executable, work_end=work_end, cancellation=cancellation, _run=_run)
        from .git_fetch_transaction import Launch
        core._need(type(launch) is Launch, "authorization")
        self.launch, self._remote = launch, _remote
        self._selected_target = None

    def _session(self):
        core._need(not self._unknown, "unknown")
        session = _Session(self)
        self._active_sessions.append(session)
        session.discover()
        return session

    def _capture(self, session, remote, selected, revision, reference_revision, *, metadata=False):
        core._need(type(selected) is Target and (selected.selected.oid is None if metadata else selected.selected.oid is not None),
                   "invalid-input")
        target = target_ref(remote, selected.selected.reference)
        self._selected_target = target
        before = session.snapshot()
        self._expected(before, revision)
        core._need(session.reference_revision(before.public) == reference_revision, "stale-observation")
        self._policy(before, "fetch")
        core._need("required-signing" not in before.public.restrictions, "required-signing")
        _configuration(before.config, remote, selected)
        require(not session.originals.shallow)
        require(not any(path.split("/")[-1] in (".gitattributes", ".lfsconfig", ".gitmodules")
                        for path in before.entries))
        directories = dict(session.originals.directories)
        require(target.rsplit("/", 1)[0] in directories, "fetch-ref-parent")
        require(not any(name.casefold() == target.casefold() for name in directories), "fetch-ref-parent")
        for name, _, _ in session.originals.files:
            if name.startswith("refs/") and name != target:
                require(name.casefold() != target.casefold() and not name.casefold().startswith(target.casefold() + "/"),
                        "fetch-ref-parent")
        expected = session.remote_tip(target)
        log = _logging(session, target)
        session.fetch_log = log
        session.check_original(); session.guard_current()
        return FetchPlan(remote, selected, reference_revision, expected, self._key, before, log)

    @core._session_boundary
    def prepare_fetch(self, remote, selected, *, expected_revision, expected_reference_revision):
        core._need(not self._retained and not self._apply_entered, "recovery-required")
        plan = self._capture(self._session(), remote, selected, expected_revision, expected_reference_revision)
        return FetchReview(plan, _review_digest(plan))

    @core._session_boundary
    def prepare_remote(self, remote, selected, *, expected_revision, expected_reference_revision):
        from .git_fetch_transaction import FetchTransaction
        core._need(not self._retained and not self._apply_entered and callable(self._remote), "authorization")
        session = self._session()
        plan = self._capture(session, remote, selected, expected_revision, expected_reference_revision, metadata=True)
        transaction = self._transaction = FetchTransaction(session, plan._snapshot, plan, None, "")
        primary = None
        try:
            oid = transaction.metadata()
            plan.target = replace(selected, selected=Selection(selected.selected.reference, oid))
        except ProcessError as error:
            self._unknown |= error.fatal
            primary = error
        except BaseException as error:
            self._unknown |= not isinstance(error, (core.GitError, OSError))
            primary = error
        try:
            if self._unknown or not transaction.close():
                transaction.retained = self._unknown = True
                self._retained.append(transaction)
        except BaseException:
            self._unknown = transaction.retained = True
            if transaction not in self._retained:
                self._retained.append(transaction)
            if primary is None:
                raise
        # Preserve the exact first process/interruption failure. A later
        # cleanup ambiguity stays latched on the same owner, not a replacement
        # ordinary GitError which would hide the original lifetime evidence.
        if primary is not None:
            raise primary
        core._need(not self._unknown, "unknown")
        session.check_original(); session.guard_current()
        return FetchReview(plan, _review_digest(plan))

    @core._session_boundary
    def apply_fetch(self, review, owner, *, expected_digest):
        from .git_fetch_transaction import FetchTransaction
        core._need(type(review) is FetchReview and type(review.plan) is FetchPlan and review.plan._key is self._key
                   and not review.plan._used and not self._apply_entered and not self._retained, "already-used")
        core._need(review.digest == expected_digest == _review_digest(review.plan), "stale-observation")
        self._apply_entered = True
        plan = review.plan
        self._active_plan, self._active_owner = plan, owner
        tx = None
        state, settlement, reason = "failed", "settled", None
        try:
            owner.check_current(self.root, "fetch", plan._snapshot.public.revision)
            session = self._session()
            current = self._capture(session, plan.remote, plan.target, plan._snapshot.public.revision, plan.reference_revision)
            core._need(_review_digest(current) == review.digest, "stale-observation")
            plan._used = True
            # Equal tips are a genuine held Prepare review, not permission to
            # repeat network/ODB work. Native Apply also refuses this before GO.
            require(plan.expected_target != plan.target.selected.oid, "fetch-up-to-date")
            tx = self._transaction = FetchTransaction(session, current._snapshot, plan, owner, review.digest)
            tx.acquire()
            tx.download()
            tx.validate_candidate()
            tx.handoff()
            tx.publish()
            state = "succeeded"
        except ProcessError as error:
            if error.fatal:
                self._unknown = True
                state, settlement, reason = "unknown", "unknown", "unknown"
            else:
                state, reason = ("recovery-required", "recovery-required") if tx and tx.intent is not None else ("failed", "command-failed")
        except (core.GitError, OSError) as error:
            state = "recovery-required" if tx and tx.intent is not None else "failed"
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
                    tx.retained = True; self._retained.append(tx)
                    state, reason = "recovery-required", "recovery-required"
                if tx.retained and tx not in self._retained:
                    # A known failed child may have private outputs requiring
                    # manual audit. Keep their original owner, not only a path.
                    self._retained.append(tx)
                    if state == "failed":
                        state = "recovery-required"
                if tx.uncertain_closes or tx.config_lock.unknown or tx.unknown:
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
        # No manufactured refreshed GitRead observation. The caller invalidates
        # its old view at Apply admission; an explicit later Observe is distinct.
        return core.MutationResult(core._text(owner.operation_id, 128), "fetch", state, settlement, reason, None,
                                   None if tx is None else tx.intent)

    def _refuse_other_write(self, *args, **kwargs):
        raise core.GitError("invalid-input")

    prepare_local = prepare_stage = prepare_unstage = prepare_commit = apply_review = apply = reconcile = _refuse_other_write
