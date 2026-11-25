"""One reviewed, local, same-parent attached-branch rename.

This is a facet of the original GitLocal owner, not a Git executor, journal or
authorization source. Stock Git makes candidates in private owned storage.
Only the original transaction may publish their bounded metadata successors;
unknown/partial effects are retained, never retried or automatically undone.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import math
import os
from pathlib import Path
import re
import stat
import time

from . import git_repository_branches as branches
from . import git_repository_local as local
from . import git_repository_read as read
from . import git_repository_switch as switch
from . import git_service as core
from .owned_process import ProcessError

MAX_CONFIG = 60 * 1024
MAX_LOG = 60 * 1024
MAX_INDEX = 1024 * 1024
REASONS = frozenset(("rename-layout", "rename-target", "rename-config", "rename-log",
                     "rename-log-missing", "rename-identity-required", "rename-packed"))


class RenameError(core.GitError):
    def __init__(self, reason):
        core._need(reason in REASONS, "invalid-input")
        super().__init__("invalid-input")
        self.reason = reason


def need(value, reason="rename-layout"):
    if not value:
        raise RenameError(reason)


def directory(path):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o7022)
    return (*core._identity(info), info.st_uid, info.st_gid)


def regular(path, limit):
    stamp, raw = core._read(path, limit)
    need(stamp.kind == "file")
    info = path.lstat()
    need(core._identity(info) == stamp.identity and info.st_uid == os.getuid()
         and info.st_nlink == 1 and not info.st_mode & 0o7022)
    return stamp, raw


def config_move(raw: bytes, config: dict, old: str, new: str) -> bytes | None:
    """Comparison template only. The actual candidate comes from stock Git.

    A missing old section is a supported no-config-change case. Repeated,
    escaped, legacy, case-aliased or destination sections are NOT absence.
    The small canonical section syntax is what ordinary `git config` writes.
    Values/comments/other sections must stay byte-for-byte identical.
    """
    need(type(raw) is bytes and len(raw) <= MAX_CONFIG and b"\0" not in raw and b"\r" not in raw,
         "rename-config")
    found, offset = [], 0
    for line in raw.splitlines(keepends=True):
        stripped = line.lstrip(b" \t")
        if re.match(rb"\[branch(?:[ .\t\]])", stripped, re.I):
            match = re.fullmatch(rb'\[branch "([A-Za-z0-9][A-Za-z0-9._/-]*)"\]\n', line)
            need(match is not None, "rename-config")
            name = match[1].decode("ascii")
            need(name.casefold() != new.casefold(), "rename-target")
            if name.casefold() == old.casefold():
                need(name == old, "rename-config")
                found.append((offset, offset + len(line)))
        offset += len(line)
    prefix = "branch." + old + "."
    keys = [key for key in config if key.startswith(prefix)]
    need(len(found) <= 1 and (bool(found) or not keys), "rename-config")
    need(all(len(config[key]) == 1 for key in keys), "rename-config")
    if not found:
        return None
    start, end = found[0]
    candidate = raw[:start] + ('[branch "' + new + '"]\n').encode("ascii") + raw[end:]
    need(len(candidate) <= MAX_CONFIG, "rename-config")
    return candidate


def renamed_config(config, old, new):
    prefix, target = "branch." + old + ".", "branch." + new + "."
    return {target + key[len(prefix):] if key.startswith(prefix) else key: values
            for key, values in config.items()}


@dataclass(frozen=True, slots=True, repr=False)
class Controls:
    files: tuple  # (fixed relative name, original stamp, private bytes)
    parents: tuple  # log-parent identity + exact original direct-name roster
    config_candidate: bytes | None
    identity: core.CommitIdentity
    logging: bool

    def comparison(self):
        return ([(n, s.kind, s.identity, s.digest) for n, s, _ in self.files], self.parents,
                None if self.config_candidate is None else core._digest(self.config_candidate),
                self.identity.name, self.identity.email, self.logging)

    def file(self, name):
        return next((stamp, raw) for selected, stamp, raw in self.files if selected == name)


@dataclass(slots=True, repr=False)
class RenamePlan:
    name: str
    reference_revision: str
    _key: object
    _snapshot: core._Snapshot
    _controls: Controls
    _used: bool = False
    action: str = field(default="branch-rename", init=False)

    @property
    def source(self):
        return self._snapshot.public.branch

    @property
    def old_name(self):
        return self.source[len("refs/heads/"):]

    @property
    def target(self):
        return "refs/heads/" + self.name

    def public(self):
        value = self._snapshot.public
        return {"action": self.action, "name": self.name, "targetRef": self.target,
                "expectedRevision": value.revision, "expectedReferenceRevision": self.reference_revision,
                "head": value.head, "branch": value.branch, "expectedIndex": self._snapshot.index_stamp.digest,
                "configMoved": self._controls.config_candidate is not None, "logging": self._controls.logging,
                "originalConfig": self._controls.file("config")[0].digest,
                "originalLog": self._controls.file("logs/" + self.source)[0].digest,
                "originalHeadLog": self._controls.file("logs/HEAD")[0].digest}


def review_digest(plan):
    core._need(type(plan) is RenamePlan, "invalid-input")
    return switch._hash({"domain": "mrk-local-branch-rename/1", "public": plan.public(),
                         "private": plan._controls.comparison()})


@dataclass(frozen=True, slots=True, repr=False)
class RenameReview:
    plan: RenamePlan
    digest: str

    def as_dict(self):
        return {**self.plan.public(), "reviewDigest": self.digest}


@dataclass(frozen=True, slots=True)
class RenameIntent:
    expected_revision: str
    expected_reference_revision: str
    expected_ref: str
    expected_head: str
    expected_index: str
    target_ref: str
    original_config: str
    candidate_config: str
    original_log: str
    candidate_log: str
    original_head_log: str
    candidate_head_log: str
    config_moved: bool
    logging: bool
    action: str = field(default="branch-rename", init=False)

    def as_dict(self):
        return {"action": self.action, "expectedRevision": self.expected_revision,
                "expectedReferenceRevision": self.expected_reference_revision, "expectedRef": self.expected_ref,
                "expectedHead": self.expected_head, "expectedIndex": self.expected_index,
                "targetRef": self.target_ref, "expectedTargetAbsent": True,
                "originalConfig": self.original_config, "candidateConfig": self.candidate_config,
                "originalLog": self.original_log, "candidateLog": self.candidate_log,
                "originalHeadLog": self.original_head_log, "candidateHeadLog": self.candidate_head_log,
                "configMoved": self.config_moved, "logging": self.logging}


def steps(value):
    controls = value._controls if type(value) is RenamePlan else value
    logging = controls.logging
    moved = controls.config_candidate is not None if type(controls) is Controls else controls.config_moved
    return (*(("new-log", "old-log") if logging else ()), "ref",
            *(("head-log",) if logging else ()), "head", *(("config",) if moved else ()))


class _RenameSession(branches._BranchSession):
    def __init__(self, repository):
        super().__init__(repository)
        self.rename_plan = None
        self.ref_locks = repository._ref_locks
        self.execution_command = None
        self.exec_view = None

    def guard_current(self):
        self.checkpoint()
        owner, revision = self.repository._active_owner, self.repository._apply_expected_revision
        if revision is not None:
            core._need(owner is not None, "authorization")
            owner.check_current(self.root, "branch-rename", revision)
        self.checkpoint()

    def names(self, path):
        rows = super().names(path)
        locks = self.ref_locks
        if locks is not None and path == locks.parent:
            locks.check()
            names = {p.name for p in locks.paths}
            core._need(names <= set(rows), "stale-observation")
            rows = tuple(n for n in rows if n not in names)
        return rows

    def discover(self):
        super().discover()
        if self.ref_locks is not None:
            self.originals = self.ref_locks.comparison(self.originals)

    def check_original(self):
        if self.ref_locks is not None:
            self.ref_locks.check()
        current = read._inventory(self.git_dir, self.checkpoint, self.names)
        original = self.originals
        if self.ref_locks is not None:
            current = self.ref_locks.comparison(current)
            original = self.ref_locks.comparison(original)
        transaction = self.repository._transaction
        expected = transaction.expected_inventory(original) if transaction is not None else original
        hooks = self._hooks()
        if self.hooks is None:
            self.hooks = hooks
        core._need(current == expected and self.hooks == hooks, "stale-observation")
        self.check_object_parents()
        if transaction is not None:
            transaction.check_controls()
        elif self.rename_plan is not None:
            controls = self.rename_plan._controls
            for name, stamp, _ in controls.files:
                core._need(core._read(self.git_dir / name, MAX_LOG + 4096)[0] == stamp, "stale-observation")
            for path, identity, names in controls.parents:
                core._need(directory(self.git_dir / path) == identity
                           and tuple(self.names(self.git_dir / path)) == names, "stale-observation")

    def command_spec(self, args, *, index=None, identity=None):
        if self.execution_command is None:
            return super().command_spec(args, index=index, identity=identity)
        transaction = self.repository._transaction
        core._need(transaction is not None and transaction.session is self
                   and (tuple(args), index, identity) == self.execution_command, "authorization")
        transaction.check_original()
        seed = ["ls-files", "--stage", "-z"]
        argv, environment = read._ReadSession.command_spec(self, seed)
        argv = [*argv[:-len(seed)], *args]
        argv[argv.index("--git-dir=" + str(self.frozen.root))] = "--git-dir=" + str(self.exec_view.root)
        environment.update(GIT_INDEX_FILE=str(transaction.index), HOME=str(self.exec_view.root),
                           XDG_CONFIG_HOME=str(self.exec_view.root))
        if identity is not None:
            core._need(identity is transaction.plan._controls.identity, "authorization")
            environment.update(GIT_COMMITTER_NAME=identity.name, GIT_COMMITTER_EMAIL=identity.email)
        return argv, environment

    def execute_private(self, args, *, identity=None):
        transaction = self.repository._transaction
        core._need(transaction is not None and transaction.session is self and self.execution_command is None,
                   "authorization")
        transaction.admit_command(args, identity)
        self.execution_command = tuple(args), transaction.index, identity
        try:
            return self.git(args, index=transaction.index, identity=identity, limit=65536)
        finally:
            self.execution_command = None

    def git(self, args, *, index=None, accept=(0,), limit=core.MAX_GIT_BYTES, identity=None):
        if self.execution_command is None:
            return super().git(args, index=index, accept=accept, limit=limit, identity=identity)
        self.guard_current()
        transaction = self.repository._transaction
        core._need(transaction is not None and transaction.session is self and accept == (0,), "authorization")
        argv, environment = self.command_spec(args, index=index, identity=identity)
        self.calls += 1
        remaining = self.deadline - time.monotonic()
        core._need(self.calls <= core.MAX_CALLS and 0 < limit <= 65536, "limit")
        core._need(remaining >= 1, "deadline")
        result = self.repository._run(argv, cwd=self.frozen.root, environ=environment, capture=True, text=False,
            timeout=min(10, math.floor(remaining)), output_limit=limit,
            cancellation=self.repository.cancellation, execution_scope=None)
        core._need(result.args == argv and type(result.returncode) is int and type(result.stdout) is bytes
                   and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= limit,
                   "response-invalid")
        core._need(result.returncode == 0, "command-failed")
        if transaction.command_entered is not None:
            transaction.command_did_return(args, result)
        self.guard_current()
        return result.returncode, result.stdout


class GitRenameRepository(branches.GitBranchesRepository):
    def __init__(self, *args, _ref_locks=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._ref_locks = _ref_locks
        self._apply_expected_revision = None

    def _session(self):
        core._need(not self._unknown, "unknown")
        session = _RenameSession(self)
        self._active_sessions.append(session)
        session.discover()
        return session

    def _capture_rename(self, session, name, expected_revision, expected_reference_revision):
        name = branches.branch_name(name)
        core._need(type(expected_reference_revision) is str and core._REVISION.fullmatch(expected_reference_revision),
                   "invalid-input")
        before = session.snapshot()
        self._expected(before, expected_revision)
        core._need(session.reference_revision(before.public) == expected_reference_revision, "stale-observation")
        self._policy(before, "branch-rename")
        core._need("required-signing" not in before.public.restrictions, "required-signing")
        source, head, target = before.public.branch, before.public.head, "refs/heads/" + name
        need(head is not None and source is not None and before.index_stamp.kind == "file"
             and len(before.index_bytes) <= MAX_INDEX)
        old = branches.branch_name(source[len("refs/heads/"):])
        need(source.rsplit("/", 1)[0] == target.rsplit("/", 1)[0] and source.casefold() != target.casefold(), "rename-target")
        need(before.config.get("core.sharedrepository", (b"false",)) in ((b"false",), (b"0",)))
        for fixed in ("worktrees", "info/sparse-checkout"):
            need(core._read(session.git_dir / fixed, 65536, regular=False)[0].kind == "absent")
        rows = session.catalog()
        try:
            branches._absent_target(tuple(row for row in rows if row.ref != source), target)
        except branches.BranchError:
            raise RenameError("rename-target") from None
        directories = dict(session.originals.directories)
        need(target.rsplit("/", 1)[0] in directories
             and not any(n.casefold() == target.casefold() for n in directories), "rename-target")
        loose, raw_ref = regular(session.git_dir / source, 65)
        need(raw_ref == (head + "\n").encode("ascii"))
        packed = session.originals.body("packed-refs")
        # A shadowed packed old ref would reappear after moving the loose ref.
        # Match a complete ref field only; stock Git still resolves all refs.
        need(not any(line.endswith(b" " + source.encode("ascii")) for line in packed.splitlines()), "rename-packed")
        for name_to_check in (target, "logs/" + target):
            need(core._read(session.git_dir / name_to_check, MAX_LOG, regular=False)[0].kind == "absent", "rename-target")
        config_stamp, raw_config = regular(session.git_dir / "config", MAX_CONFIG)
        candidate = config_move(raw_config, before.config, old, name)
        # Replacement inherits the same held parent's group on supported
        # native filesystems. Ref moves preserve their inode/group instead.
        git_group = session.git_dir.lstat().st_gid
        need((session.git_dir / "HEAD").lstat().st_gid == git_group
             and (candidate is None or (session.git_dir / "config").lstat().st_gid == git_group))
        try:
            identity = branches._local_identity(before.config)
        except branches.BranchError:
            raise RenameError("rename-identity-required") from None
        logging = before.config.get("core.logallrefupdates", (b"true",))
        need(logging in ((b"true",), (b"false",)), "rename-log")
        logs, parents = [], {}
        for log_name in ("logs/" + source, "logs/HEAD"):
            parent = str(Path(log_name).parent)
            try:
                parents[parent] = (directory(session.git_dir / parent), tuple(session.names(session.git_dir / parent)))
            except FileNotFoundError:
                raise RenameError("rename-log-missing") from None
            stamp, body = core._read(session.git_dir / log_name, MAX_LOG)
            need(stamp.kind in ("file", "absent") and (not body or body.endswith(b"\n")), "rename-log")
            if stamp.kind == "file":
                regular(session.git_dir / log_name, MAX_LOG)
                need((session.git_dir / log_name).lstat().st_gid == (session.git_dir / parent).lstat().st_gid)
            logs.append((log_name, stamp, body))
        present = [s.kind == "file" for _, s, _ in logs]
        need(present[0] == present[1], "rename-log")
        need(present[0] or logging == (b"false",), "rename-log-missing")
        for parent, (_, names) in parents.items():
            core._need(len(names) <= 512, "limit")
            if parent == str(Path("logs/" + target).parent):
                need(not any(n.casefold() == Path(target).name.casefold() for n in names), "rename-target")
        controls = Controls(((source, loose, raw_ref), ("config", config_stamp, raw_config), *logs),
                            tuple((p, *v) for p, v in sorted(parents.items())), candidate, identity, present[0])
        plan = RenamePlan(name, expected_reference_revision, self._key, before, controls)
        session.rename_plan = plan
        session.check_original()
        session._check_frozen()
        return plan

    @core._session_boundary
    def prepare_rename(self, name, *, expected_revision, expected_reference_revision):
        core._need(not self._retained and not self._apply_entered, "recovery-required")
        plan = self._capture_rename(self._session(), name, expected_revision, expected_reference_revision)
        return RenameReview(plan, review_digest(plan))

    @core._session_boundary
    def apply_rename(self, review, owner, *, expected_digest):
        core._need(type(review) is RenameReview and type(review.plan) is RenamePlan and review.plan._key is self._key
                   and not review.plan._used and not self._apply_entered and not self._retained, "already-used")
        core._need(review.digest == expected_digest == review_digest(review.plan), "stale-observation")
        self._apply_entered = True
        session = self._session()
        current = self._capture_rename(session, review.plan.name, review.plan._snapshot.public.revision,
                                       review.plan.reference_revision)
        core._need(review_digest(current) == review.digest, "stale-observation")
        review.plan._used = True
        return self._apply_captured(session, RenameReview(current, review.digest), owner)

    def _apply_captured(self, session, review, owner):
        from .git_rename_transaction import BorrowedRefLocks, RefLocks, Handoff, RenameTransaction
        core._need(self._apply_entered and len(self._active_sessions) == 1 and self._active_sessions[0] is session
                   and type(session) is _RenameSession and session.repository is self and self._transaction is None
                   and type(review) is RenameReview and review.plan._key is self._key
                   and review.digest == review_digest(review.plan), "authorization")
        plan = review.plan
        handoff = Handoff(self, plan, owner)
        self._active_plan, self._active_owner = plan, handoff
        self._apply_expected_revision = plan._snapshot.public.revision
        transaction = None
        intent = observation = reason = None
        state, settlement = "failed", "settled"
        try:
            handoff.check_current(self.root, plan.action, plan._snapshot.public.revision)
            if self._ref_locks is None:
                self._ref_locks = session.ref_locks = RefLocks(self.root, plan.source, plan.target)
                self._ref_locks.acquire()
            else:
                core._need(type(self._ref_locks) is BorrowedRefLocks and self._ref_locks.source == plan.source
                           and self._ref_locks.target == plan.target, "authorization")
                self._ref_locks.check()
            session.originals = self._ref_locks.comparison(session.originals)
            transaction = self._transaction = RenameTransaction(session, plan._snapshot, plan, handoff)
            transaction.acquire()
            transaction.prepare_candidates()
            intent = transaction.intent
            handoff.record_intent(intent)
            for step in steps(plan):
                transaction.publish(step)
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
                preserve = intent is not None and state != "succeeded"
                if self._unknown:
                    transaction.retained = True
                elif not transaction.close(preserve_scratch=preserve):
                    transaction.retained = True
                    state, reason = "recovery-required", "recovery-required"
                if transaction.retained:
                    self._retained.append(transaction)
                if transaction.uncertain_closes or transaction.directory_closes or transaction.config_lock.unknown:
                    self._unknown = True
                if self._unknown:
                    state, settlement, reason = "unknown", "unknown", "unknown"
                elif state == "succeeded":
                    observation = session.snapshot().public
        except BaseException:
            self._unknown = True
            if transaction is not None and transaction not in self._retained:
                self._retained.append(transaction)
            raise
        finally:
            if not self._unknown:
                self._active_plan = self._active_owner = self._apply_expected_revision = None
        return core.MutationResult(handoff.operation_id, plan.action, state, settlement, reason, observation, intent)

    def _finish_sessions(self, uncertain):
        from .git_rename_transaction import RefLocks
        good = super()._finish_sessions(uncertain)
        if good and type(self._ref_locks) is RefLocks:
            try:
                good = self._ref_locks.close()
            except (core.GitError, OSError):
                self._unknown = self._ref_locks.unknown = True
                return False
            except BaseException:
                self._unknown = True
                raise
            if not good:
                self._unknown = True
        return good

    def _refuse_other_write(self, *args, **kwargs):
        raise core.GitError("invalid-input")

    prepare_branch = apply_branch = _refuse_other_write
