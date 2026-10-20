"""Closed local-index/commit facet over the existing Git transaction owner.

This is NOT an installed invocation, durable journal or authorization issuer.
The fixed native caller must retain its original project/tool/consent and persist
Preparing before work, then acknowledge the SAME operation's exact candidate
intent before publication. An opaque review digest is comparison DATA only.

Only ordinary .git directories are supported. Discovery and candidate commands
reuse the read facet's private config/refs. The one attached-ref CAS reads the
original configuration only while its original config.lock is held and the
unchanged no-includes policy is rechecked. Required hooks/signing/filters refuse;
there is no reset, checkout, force stage, network or generic command endpoint.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import time

from . import git_repository_read as read
from . import git_service as core

_REF_MESSAGE = "MRK: record reviewed staged changes"
_OBJECT_FANOUTS = tuple(f"{number:02x}" for number in range(256))


@dataclass(frozen=True, slots=True, repr=False)
class LocalReview:
    """An actual original core prepare, never recreated from a wire object."""
    plan: core.GitPlan
    digest: str

    def as_dict(self) -> dict:
        return {**self.plan.as_dict(), "expectedIndex": self.plan._snapshot.index_stamp.digest,
                "reviewDigest": self.digest}


def _review_digest(plan: core.GitPlan) -> str:
    value = {"review": plan.as_dict(), "index": plan._snapshot.index_stamp.digest,
             "selected": [(path, stamp.kind, stamp.identity, stamp.digest)
                          for path, stamp in sorted(plan._selected.items())],
             "message": plan._message,
             "author": None if plan._identity is None else (plan._identity.name, plan._identity.email)}
    return hashlib.sha256(b"mrk-git-local-review/1\0" + json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class _RefSuccessor:
    name: str
    oid: str
    stamp: core._Stamp
    parent: tuple[int, ...]


@dataclass(frozen=True, slots=True, repr=False)
class _IndexPublication:
    """Exact successor after this transaction's positive publication return.

    Private comparison evidence only: not a journal ACK, native settlement or
    permission to forget the original source's held OLD index descriptor.
    """
    intent: core.PublicationIntent
    original: core._Stamp
    successor: core._Stamp


def _inventory_matches(original: read._ReferenceInventory, current: read._ReferenceInventory,
                       *, objects_written: bool, successor: _RefSuccessor | None = None) -> bool:
    """Finite comparison, not an exhaustive object inventory or an ABA defense.

    Git may add content-addressed loose objects under its unchanged objects
    directory. Only that directory's timestamps/size may differ. After the
    actual positive CAS, the exact selected loose ref and its captured parent
    stamp can differ; packed-refs and every other ref remain unchanged.
    """
    if original.forbidden != current.forbidden or original.pack != current.pack:
        return False
    before_dirs, after_dirs = dict(original.directories), dict(current.directories)
    if before_dirs.keys() != after_dirs.keys():
        return False
    for name, before in before_dirs.items():
        after = after_dirs[name]
        if name == "objects" and objects_written:
            if before[:3] != after[:3]:
                return False
        elif successor is not None and name == successor.name.rsplit("/", 1)[0]:
            if before[:3] != after[:3] or after != successor.parent:
                return False
        elif before != after:
            return False
    before_files = {name: (stamp, body) for name, stamp, body in original.files}
    after_files = {name: (stamp, body) for name, stamp, body in current.files}
    if successor is not None:
        before_files[successor.name] = (successor.stamp, (successor.oid + "\n").encode("ascii"))
    return before_files == after_files


class _ConfigLock:
    """One fixed config.lock with an original, one-attempt descriptor route."""
    def __init__(self, path: Path):
        self.path = path
        self.fd: int | None = None
        self.identity: tuple[int, ...] | None = None
        self.entered = self.returned = self.close_claimed = self.closed = self.unknown = False

    def acquire(self) -> None:
        core._need(not self.entered, "already-used")
        self.entered = True
        try:
            self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except OSError as error:
            self.returned = self.closed = True  # Returned failed open: no FD.
            if isinstance(error, FileExistsError):
                raise core.GitError("locked") from None
            raise
        except BaseException:
            self.unknown = True
            raise
        self.returned = True
        # The FD is retained before either observation can fail.
        self.identity = core._identity(os.fstat(self.fd))
        self.check()

    def check(self) -> None:
        core._need(self.entered and self.returned and not self.closed and not self.close_claimed
                   and not self.unknown and self.fd is not None and self.identity is not None, "recovery-required")
        core._need(core._identity(os.fstat(self.fd)) == self.identity
                   and core._identity(self.path.lstat()) == self.identity, "stale-observation")

    def close(self) -> bool:
        if self.closed:
            return not self.unknown
        if not self.entered:
            self.closed = True
            return True
        if self.close_claimed or not self.returned or self.fd is None:
            self.unknown = True
            return False
        self.close_claimed = True  # Retire before unlink/close can lose return.
        good = True
        try:
            if self.identity is None or core._identity(self.path.lstat()) != self.identity:
                good = False  # Never unlink a foreign/replaced lock.
            else:
                os.unlink(self.path)
        except OSError:
            good = False
        finally:
            self.unknown = True
            os.close(self.fd)  # Exactly one close attempt of this original FD.
            self.closed = True
            self.unknown = False
        return good


class _IntentHandoff:
    """One delegate to the genuine owner, not another authorization source."""
    def __init__(self, repository: GitLocalRepository, plan: core.GitPlan, original: core.MutationOwner):
        self.repository, self.plan, self.original = repository, plan, original
        self.operation_id = original.operation_id
        self.entered = self.acknowledged = False
        self.intent: core.PublicationIntent | None = None

    def check_current(self, root: Path, action: str, expected_revision: str) -> None:
        core._need(root == self.repository.root and action == self.plan.action
                   and expected_revision == self.plan._snapshot.public.revision, "authorization")
        self.original.check_current(root, action, expected_revision)

    def record_intent(self, intent: core.PublicationIntent) -> None:
        core._need(not self.entered and type(intent) is core.PublicationIntent, "already-used")
        before = self.plan._snapshot
        core._need((intent.action, intent.expected_revision, intent.expected_ref, intent.expected_head,
                    intent.expected_index) == (self.plan.action, before.public.revision, before.public.branch,
                                               before.public.head, before.index_stamp.digest), "authorization")
        transaction = self.repository._transaction
        core._need(transaction is not None, "authorization")
        if self.plan.action == "commit":
            core._need(intent.candidate_index is None and intent.candidate_commit is not None
                       and intent.candidate_commit == transaction.session.commit_oid, "authorization")
        else:
            core._need(intent.candidate_commit is None and transaction.index is not None
                       and intent.candidate_index == core._read(transaction.index, core.MAX_INDEX_BYTES)[0].digest,
                       "authorization")
        # Retain the exact sent intent BEFORE entering the existing native
        # journal handoff. A missing/unknown return never permits another send.
        self.entered, self.intent = True, intent
        self.original.record_intent(intent)
        transaction.session.guard_current()
        self.acknowledged = True

    def publication_ready(self, *, candidate_index: Path | None = None) -> None:
        core._need(self.acknowledged and self.intent is not None, "authorization")
        if candidate_index is not None:
            stamp, _ = core._read(candidate_index, core.MAX_INDEX_BYTES)
            core._need(stamp.kind == "file" and stamp.digest == self.intent.candidate_index,
                       "recovery-required")


class _LocalTransaction(core._IndexTransaction):
    def __init__(self, session: _LocalSession, original: core._Snapshot,
                 plan: core.GitPlan, owner: _IntentHandoff):
        super().__init__(session, original)
        self.plan, self.owner = plan, owner
        self.config_lock = _ConfigLock(session.git_dir / "config.lock")
        self.publishing_index = False
        self.index_publication: _IndexPublication | None = None

    def acquire(self) -> None:
        if self.plan.action == "commit":
            self.session.require_ref_parent(self.plan._snapshot.public.branch)
        self.config_lock.acquire()
        self.session.check_original()
        # Reparse only the retained private copy, now while ordinary Git config
        # writers are excluded. Includes have never been loaded by any command.
        self.session.recensus()
        self.session.guard_current()
        super().acquire()

    def check_original(self) -> None:
        self.config_lock.check()
        self.session.check_original()
        super().check_original()
        if self.publishing_index:
            self.owner.publication_ready(candidate_index=self.index)
        # Also runs after the index-lock fsync, immediately before replacement.
        # A returned candidate ACK never suppresses subsequent STOP checks.
        self.session.guard_current()

    def publish_index(self) -> None:
        core._need(not self.publishing_index, "already-used")
        self.owner.publication_ready(candidate_index=self.index)
        self.publishing_index = True
        super().publish_index()
        # A positive original rename/fsync return is necessary, not just a
        # matching file at the name. The native source still closes its OLD
        # index FD; this comparison does not replace or relinquish that owner.
        assert self.session.git_dir is not None
        self.owner.publication_ready(candidate_index=self.session.git_dir / "index")
        successor, _ = core._read(self.session.git_dir / "index", core.MAX_INDEX_BYTES)
        intent = self.owner.intent
        core._need(intent is not None and successor.kind == "file" and successor.digest == intent.candidate_index
                   and successor.identity == core._identity(os.fstat(self.locks[0][1])), "recovery-required")
        # Unlike the base's early `published` flag, this is set only AFTER its
        # rename, directory fsync/close and these exact successor checks return.
        self.index_publication = _IndexPublication(intent, self.original.index_stamp, successor)

    def close(self, *, preserve_scratch: bool = False) -> bool:
        first = None
        try:
            good = super().close(preserve_scratch=preserve_scratch)
        except BaseException as error:
            first, good = error, False
        try:
            good = self.config_lock.close() and good
        except BaseException:
            if first is None:
                raise
        if first is not None:
            raise first
        if self.config_lock.unknown:
            # The base owner sees its own close routes only. A lost config FD
            # close must also retain this repository/session as UNKNOWN.
            self.session.repository._unknown = True
        self.retained |= not good or self.config_lock.unknown
        return good


class _LocalSession(read._ReadSession):
    def __init__(self, repository: GitLocalRepository):
        super().__init__(repository)
        self.hooks: tuple | None = None
        self.objects_written = False
        self.successor: _RefSuccessor | None = None
        self.tree_oid = self.commit_oid = None
        self.blob_bytes = 0
        self.recensusing = False
        self.object_parents: dict[str, tuple[int, ...] | None] | None = None
        self.object_additions: dict[str, tuple[int, ...]] = {}
        self._resolved_head: tuple[str | None, str | None] | None = None

    def guard_current(self) -> None:
        self.checkpoint()
        plan, owner = self.repository._active_plan, self.repository._active_owner
        if plan is not None:
            core._need(owner is not None, "authorization")
            owner.check_current(self.root, plan.action, plan._snapshot.public.revision)
        self.checkpoint()

    def _hooks(self) -> tuple:
        names = ("hooks", *("hooks/" + name for name in sorted(core._ACTIVE_HOOKS)))
        values = []
        assert self.git_dir is not None
        # Check the fixed parent before looking below it. Hook contents are
        # never read, copied, interpreted or invoked by this census.
        try:
            parent = (self.git_dir / "hooks").lstat()
        except FileNotFoundError:
            return (("hooks", None),)
        core._need(stat.S_ISDIR(parent.st_mode), "unsupported-repository")
        for name in names:
            self.checkpoint()
            try:
                info = (self.git_dir / name).lstat()
            except FileNotFoundError:
                values.append((name, None))
            else:
                values.append((name, core._identity(info)))
        return tuple(values)

    def check_original(self) -> None:
        assert self.git_dir is not None and self.originals is not None
        current = read._inventory(self.git_dir, self.checkpoint, self.names)
        core._need(_inventory_matches(self.originals, current, objects_written=self.objects_written,
                                      successor=self.successor), "stale-observation")
        hooks = self._hooks()
        if self.hooks is None:
            self.hooks = hooks
        core._need(self.hooks == hooks, "stale-observation")
        self.check_object_parents()

    def check_object_parents(self, *, accept_additions: bool = False) -> None:
        """Fixed no-follow parent census, not an exhaustive object inventory.

        Only a positive, exact candidate-writing command may admit an absent
        fanout becoming a real owned directory. Existing directory identities
        never change. Timestamp tolerance after our content-addressed writes
        is a bounded cooperation policy, NOT hostile namespace/ABA protection.
        """
        assert self.git_dir is not None
        current = {}
        for name in _OBJECT_FANOUTS:
            self.checkpoint()
            try:
                info = (self.git_dir / "objects" / name).lstat()
            except FileNotFoundError:
                current[name] = None
                continue
            core._need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                       and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH), "unsupported-repository")
            current[name] = (*core._identity(info), info.st_uid, info.st_gid)
        if self.object_parents is None:
            self.object_parents = current
            return
        additions = {}
        for name, before in self.object_parents.items():
            before = self.object_additions.get(name, before)
            after = current[name]
            if before is None and after is not None:
                core._need(accept_additions and self.objects_written, "stale-observation")
                additions[name] = after
            elif before is not None and after is not None and self.objects_written:
                core._need(before[:3] == after[:3] and before[6:] == after[6:], "stale-observation")
            else:
                core._need(before == after, "stale-observation")
        self.object_additions.update(additions)

    def require_ref_parent(self, branch: str | None) -> None:
        core._need(branch is not None and core._ref(branch), "unsupported-repository")
        # All original ref ancestors already passed the finite inventory's
        # no-follow checks. This slice cannot create an absent nested parent.
        assert self.originals is not None
        core._need(branch.rsplit("/", 1)[0] in dict(self.originals.directories), "unsupported-repository")

    def _check_frozen(self) -> None:
        """Rematch this existing scratch owner's exact finite file/dir roster.

        A changed private ref must not be hidden by a resolved-head cache. This
        neither resolves Git refs nor adopts a new entry into the original view.
        """
        core._need(not self.repository._unknown and self.frozen is not None and not self.frozen.unknown, "unknown")
        core._need(any(session is self for session in self.repository._active_sessions)
                   and self.frozen.root in self.frozen.directories, "already-used")
        for path, identity in self.frozen.directories.items():
            self.checkpoint()
            before = core._identity(path.lstat())
            core._need(before[:2] == identity and stat.S_ISDIR(before[2]), "stale-observation")
            expected = {entry.name for entry in (*self.frozen.directories, *self.frozen.files)
                        if entry != path and entry.parent == path}
            core._need(set(self.names(path)) == expected and core._identity(path.lstat()) == before,
                       "stale-observation")
        for path, stamp in self.frozen.files.items():
            self.checkpoint()
            core._need(core._read(path, 65536)[0] == stamp, "stale-observation")

    def head(self) -> tuple[str | None, str | None]:
        # Git resolves the exact copied refs once. Reuse only within this same
        # view while BOTH real originals and every private entry remain exact;
        # the cached tuple supplies no publication or process-finality receipt.
        self.guard_current()
        self._check_frozen()
        self.check_original()
        resolved = self._resolved_head
        if resolved is None:
            resolved = core._Session.head(self)
        self.check_original()
        self.guard_current()
        self._check_frozen()
        self._resolved_head = resolved
        return resolved

    def recensus(self) -> None:
        core._need(not self.recensusing and self.frozen is not None, "already-used")
        self.check_original()
        self.recensusing = True
        try:
            _, raw = self.git(["config", "--file", str(self.frozen.root / read._CONFIG_FILE),
                               "--no-includes", "--null", "--list"], limit=65536)
            core._need(read._configuration(raw) == self.config, "stale-observation")
        finally:
            self.recensusing = False
        self.check_original()

    def validate_paths(self, paths, snapshot, *, staging):
        core._need(all(len(path.split("/")) <= read.MAX_REF_DEPTH for path in paths), "unsupported-path")
        if staging:
            # Ignored/unobserved targets never get force-staged. Tracked changed
            # files remain ordinary Git files, even if an ignore rule matches.
            visible = {row.path for row in snapshot.public.changes if row.index != "!"}
            core._need(all(path in visible for path in paths), "unsupported-path")
        return super().validate_paths(paths, snapshot, staging=staging)

    def _extra_arguments(self, args: list[str], index, identity) -> bool:
        if args[:2] == ["cat-file", "blob"] and len(args) == 3:
            return index is None and identity is None and core._OID.fullmatch(args[2]) is not None
        plan, transaction = self.repository._active_plan, self.repository._transaction
        if plan is None or transaction is None or transaction.session is not self:
            return False
        candidate = index == transaction.index and index is not None
        if args == ["add", "--all", "--", *plan.paths]:
            return candidate and identity is None and plan.action == "stage"
        if plan.action == "unstage" and identity is None and candidate:
            head = plan._snapshot.public.head
            return args == (["update-index", "--force-remove", "--", *plan.paths] if head is None else
                            ["restore", "--staged", "--source=" + head, "--", *plan.paths])
        if plan.action != "commit":
            return False
        if args == ["write-tree"]:
            return candidate and identity is None
        if self.tree_oid is not None:
            expected = ["commit-tree", self.tree_oid]
            if plan._snapshot.public.head is not None:
                expected += ["-p", plan._snapshot.public.head]
            expected += ["-m", plan._message]
            if args == expected:
                return candidate and identity is plan._identity
        expected = ["update-ref", "--no-deref", "-m", _REF_MESSAGE, plan._snapshot.public.branch,
                    self.commit_oid, plan._snapshot.public.head or "0" * len(self.commit_oid or "")]
        return self.commit_oid is not None and index is None and identity is None and args == expected

    def command_spec(self, args: list[str], *, index=None, identity=None) -> tuple[list[str], dict[str, str]]:
        core._need(type(args) is list and args and all(type(value) is str for value in args), "invalid-input")
        assert self.frozen is not None and self.git_dir is not None
        ordinary = read._read_arguments(args, self.frozen.root / read._CONFIG_FILE)
        core._need(ordinary or self._extra_arguments(args, index, identity), "invalid-input")
        if ordinary:
            core._need(identity is None, "invalid-input")
            if index is not None:
                transaction = self.repository._transaction
                core._need(transaction is not None and transaction.session is self and index == transaction.index
                           and args == ["ls-files", "--stage", "-z"], "invalid-input")
            argv, environment = super().command_spec(args)
        else:
            seed = ["ls-files", "--stage", "-z"]
            argv, environment = super().command_spec(seed)
            argv = [*argv[:-len(seed)], *args]
        if index is not None:
            environment["GIT_INDEX_FILE"] = str(index)
        if identity is not None:
            identity.validate()
            environment.update(GIT_AUTHOR_NAME=identity.name, GIT_AUTHOR_EMAIL=identity.email,
                               GIT_COMMITTER_NAME=identity.name, GIT_COMMITTER_EMAIL=identity.email)
        if args[0] == "update-ref":
            transaction = self.repository._transaction
            core._need(transaction is not None and not transaction.retained, "authorization")
            transaction.owner.publication_ready()
            transaction.config_lock.check()
            # This is the ONLY command that can load original local config.
            # Its still-held config.lock + exact no-includes census excludes
            # ordinary config writes. No option/HEAD target comes from IPC.
            argv[argv.index("--git-dir=" + str(self.frozen.root))] = "--git-dir=" + str(self.git_dir)
        return argv, environment

    def _accept_ref_successor(self) -> None:
        plan = self.repository._active_plan
        core._need(plan is not None and self.successor is None and self.commit_oid is not None,
                   "recovery-required")
        # A positive CAS changes this view. Invalidate BEFORE accepting or
        # writing any successor; the next head() requires fresh Git resolution.
        self._resolved_head = None
        assert self.git_dir is not None and self.originals is not None and self.frozen is not None
        branch = plan._snapshot.public.branch
        core._need(branch is not None and core._ref(branch), "recovery-required")
        current = read._inventory(self.git_dir, self.checkpoint, self.names)
        files = {name: (stamp, body) for name, stamp, body in current.files}
        selected = files.get(branch)
        core._need(selected is not None and selected[0].kind == "file"
                   and selected[1] == (self.commit_oid + "\n").encode("ascii"), "recovery-required")
        parent = dict(current.directories).get(branch.rsplit("/", 1)[0])
        core._need(parent is not None, "recovery-required")
        successor = _RefSuccessor(branch, self.commit_oid, selected[0], parent)
        core._need(_inventory_matches(self.originals, current, objects_written=self.objects_written,
                                      successor=successor), "recovery-required")
        self.successor = successor
        # Exact positive update-ref receipt + original inventory check above,
        # never a presumed success from readback of an unknown child.
        self.frozen.write(branch, selected[1])
        self.check_original()

    def git(self, args: list[str], *, index=None, accept=(0,), limit=core.MAX_GIT_BYTES, identity=None):
        self.guard_current()
        core._need(self.frozen is not None and self.git_dir is not None, "invalid-input")
        if self.initial_config or self.recensusing:
            core._need(args == ["config", "--file", str(self.frozen.root / read._CONFIG_FILE),
                                "--no-includes", "--null", "--list"], "invalid-input")
        else:
            core._need(args[0] != "config" and self.config is not None, "invalid-input")
        if not self.initial_config:
            self.check_original()
        argv, environment = self.command_spec(args, index=index, identity=identity)
        self.calls += 1
        remaining = self.deadline - time.monotonic()
        core._need(self.calls <= core.MAX_CALLS and 0 < limit <= core.MAX_GIT_BYTES, "limit")
        core._need(remaining >= 1, "deadline")
        if args[0] in ("add", "write-tree", "commit-tree"):
            self.objects_written = True  # An entered failed send may add objects.
        result = self.repository._run(argv, cwd=self.frozen.root, environ=environment, capture=True, text=False,
            timeout=min(10, math.floor(remaining)), output_limit=limit,
            cancellation=self.repository.cancellation, execution_scope=None)
        core._need(result.args == argv and type(result.returncode) is int and type(result.stdout) is bytes
                   and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= limit,
                   "response-invalid")
        core._need(result.returncode in accept, "command-failed")
        if args[0] in ("add", "write-tree", "commit-tree"):
            self.check_object_parents(accept_additions=True)
        if args[0] == "write-tree":
            self.tree_oid = core._oid(result.stdout)
        elif args[0] == "commit-tree":
            self.commit_oid = core._oid(result.stdout)
        elif args[0] == "update-ref":
            self._accept_ref_successor()
        elif args[0] == "cat-file":
            self.blob_bytes += len(result.stdout)
            core._need(self.blob_bytes <= core.MAX_SOURCE_BYTES, "limit")
        elif args[0] == "status":
            for row in core._nul(result.stdout):
                core._need(len(row) >= 4 and len(row[3:].split(b"/")) <= read.MAX_REF_DEPTH, "limit")
        self.guard_current()
        return result.returncode, result.stdout


class GitLocalRepository(core.GitRepository):
    """Finite core facade; the native caller supplies the real MutationOwner."""
    def __init__(self, root: Path, *, git_executable: Path, work_end: float, cancellation=None, _run=core.run_owned):
        core._need(type(work_end) in (int, float) and math.isfinite(work_end), "invalid-input")
        super().__init__(root, git_executable=git_executable, cancellation=cancellation, _run=_run)
        self.work_end = work_end
        self._active_owner = self._active_plan = self._transaction = None
        self._apply_entered = False

    def _session(self) -> _LocalSession:
        core._need(not self._unknown, "unknown")
        session = _LocalSession(self)
        self._active_sessions.append(session)
        session.discover()
        return session

    def _index_transaction(self, session, current):
        core._need(type(session) is _LocalSession and session.repository is self
                   and self._active_owner is not None and type(self._active_plan) is core.GitPlan
                   and self._transaction is None, "authorization")
        self._transaction = _LocalTransaction(session, current, self._active_plan, self._active_owner)
        return self._transaction

    def prepare_local(self, action: str, *, expected_revision: str, paths=(), message=None, identity=None) -> LocalReview:
        if action == "commit":
            core._need(type(paths) in (list, tuple) and not paths, "invalid-input")
            plan = super().prepare_commit(message, identity, expected_revision=expected_revision)
            # Initial slice does not create missing nested unborn ref parents.
            try:
                parent = (self.root / ".git" / plan._snapshot.public.branch).parent.lstat()
            except FileNotFoundError:
                raise core.GitError("unsupported-repository") from None
            core._need(stat.S_ISDIR(parent.st_mode), "unsupported-repository")
        else:
            core._need(action in ("stage", "unstage") and message is None and identity is None, "invalid-input")
            method = self.prepare_stage if action == "stage" else self.prepare_unstage
            plan = method(paths, expected_revision=expected_revision)
        return LocalReview(plan, _review_digest(plan))

    def apply_review(self, review: LocalReview, owner: core.MutationOwner, *, expected_digest: str) -> core.MutationResult:
        core._need(type(review) is LocalReview and review.plan._key is self._key
                   and review.digest == _review_digest(review.plan), "invalid-input")
        core._need(type(expected_digest) is str and core._REVISION.fullmatch(expected_digest) is not None,
                   "invalid-input")
        core._need(review.digest == expected_digest, "stale-observation")
        return self.apply(review.plan, owner)

    def apply(self, plan, owner):
        # Missing Root hook fails before lock/object effects, not a fallback to
        # the base service's original-config discovery/publication path.
        core._need(hasattr(core.GitRepository, "_index_transaction"), "authorization")
        core._need(not self._apply_entered and type(plan) is core.GitPlan and plan._key is self._key
                   and not plan._used, "already-used")
        self._apply_entered = True
        handoff = _IntentHandoff(self, plan, owner)
        self._active_owner, self._active_plan = handoff, plan
        try:
            return super().apply(plan, handoff)
        finally:
            if not self._unknown:
                self._active_owner = self._active_plan = None
