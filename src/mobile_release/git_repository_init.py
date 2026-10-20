"""Initialize one absent local Git directory through the existing Git owner.

Prepare is read-only. The installed caller supplies an exclusive, held private
worktree only AFTER its original durable Preparing ACK. Stock Git never runs
against the selected project's contents. The same owner's Candidate ACK then
precedes one no-replace directory move. This module is neither an executor nor
a journal/consent issuer; it borrows the caller's retained directory originals.
There is deliberately no rollback, adoption, initial commit, remote or retry.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time

from . import git_repository_read as read
from . import git_service as core
from .init_transaction import _rename_function

ACTION, BRANCH, OBJECT_FORMAT = "initialize", "main", "sha1"
PRIVATE_PREFIX = ".mrk-git-init-"
MAX_NAMES, MAX_NAME_BYTES = 4096, 256 * 1024
MAX_CONFIG = 8192
DIRECTORIES = ("", "objects", "objects/info", "objects/pack", "refs", "refs/heads", "refs/tags")
FILES = ("HEAD", "config")
REASONS = frozenset(("git-already-present", "git-init-layout", "git-init-candidate"))


class InitError(core.GitError):
    def __init__(self, reason):
        super().__init__(reason)
        if reason in REASONS:
            self.reason = reason


def _need(value, reason="git-init-layout"):
    if not value:
        raise InitError(reason)


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True).encode("ascii")).hexdigest()


def directory(info):
    _need(stat.S_ISDIR(info.st_mode) and info.st_dev > 0 and info.st_ino > 0
          and getattr(info, "st_flags", 0) == 0)
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def names(path):
    # Bound allocation while enumerating, not after constructing a full list.
    result, size = [], 0
    with os.scandir(path) as stream:
        for entry in stream:
            encoded = os.fsencode(entry.name)
            size += len(encoded)
            _need(len(result) < MAX_NAMES and size <= MAX_NAME_BYTES, "limit")
            result.append(entry.name)
    return tuple(sorted(result))


@dataclass(frozen=True, slots=True, repr=False)
class BorrowedDirectory:
    """Comparison of a real caller-held descriptor; has no close/adopt route."""
    path: Path
    fd: int
    identity: tuple

    def check(self, *, at=None):
        path = self.path if at is None else at
        _need(type(self.fd) is int and self.fd >= 0 and len(self.identity) == 5
              and directory(os.fstat(self.fd)) == self.identity
              and directory(path.lstat()) == self.identity, "stale-observation")


@dataclass(frozen=True, slots=True, repr=False)
class BorrowedCandidate:
    root: BorrowedDirectory
    outer: BorrowedDirectory
    worktree: BorrowedDirectory
    git: BorrowedDirectory
    template: BorrowedDirectory

    def check(self, *, published=False):
        name = self.outer.path.name
        _need(re.fullmatch(re.escape(PRIVATE_PREFIX) + r"[0-9a-f]{32}", name) is not None
              and self.outer.path.parent == self.root.path
              and self.worktree.path == self.outer.path / "worktree"
              and self.git.path == self.worktree.path / ".git"
              and self.template.path == self.outer.path / "empty-template", "git-init-candidate")
        for original in (self.root, self.outer, self.worktree, self.template):
            original.check()
        self.git.check(at=self.root.path / ".git" if published else None)
        _need(all(row.identity[0] == self.root.identity[0]
                  and row.identity[3] == self.root.identity[3]
                  and stat.S_IMODE(row.identity[2]) == 0o700
                  for row in (self.outer, self.worktree, self.git, self.template)), "git-init-candidate")
        _need(names(self.outer.path) == ("empty-template", "worktree")
              and names(self.template.path) == ()
              and names(self.worktree.path) == (() if published else (".git",)), "git-init-candidate")


def absence(root, private=None):
    """Current selected/enclosing layout, not a GitRead revision or build fact.

    Ordinary project files are never read or classified. A nested independent
    repository is not staged by initialization; an enclosing repo, submodule
    marker, bare layout or retained init candidate instead requires manual work.
    """
    _need(isinstance(root, Path) and root.is_absolute() and len(root.parts) <= 64)
    if private is not None:
        _need(type(private) is BorrowedCandidate and private.root.path == root)
        private.check()
    rows = []
    for index, path in enumerate((root, *root.parents)):
        before = directory(path.lstat())
        # Native SourceBook separately proves physical protected ancestry,
        # including its fixed /private/tmp alias. Do not mistake that original
        # sticky system parent for a project-owned/writable metadata leaf.
        if index == 0:
            _need(not before[2] & 0o7022)
        entries = names(path)
        folded = {name.lower() for name in entries}
        _need(".git" not in folded, "git-already-present")
        if index == 0:
            _need(".gitmodules" not in folded and "commondir" not in folded
                  and "gitdir" not in folded
                  and not ("head" in folded and ("objects" in folded or "refs" in folded)))
            for name in entries:
                if name.lower().startswith(PRIVATE_PREFIX):
                    _need(private is not None and name == private.outer.path.name, "recovery-required")
        _need(directory(path.lstat()) == before, "stale-observation")
        rows.append((str(path), before))
    if private is not None:
        private.check()
    return tuple(rows)


@dataclass(slots=True, repr=False)
class InitPlan:
    expected_revision: str
    _key: object
    _absence: tuple
    _used: bool = False

    def as_dict(self):
        return {"action": ACTION, "expectedRevision": self.expected_revision,
                "initialBranch": BRANCH, "objectFormat": OBJECT_FORMAT}


@dataclass(frozen=True, slots=True, repr=False)
class InitReview:
    plan: InitPlan
    digest: str

    def as_dict(self):
        return {**self.plan.as_dict(), "reviewDigest": self.digest}


def review_digest(plan):
    _need(type(plan) is InitPlan, "invalid-input")
    return _hash({"domain": "mrk-git-init-review/1", "review": plan.as_dict(), "absence": plan._absence})


@dataclass(frozen=True, slots=True, repr=False)
class Manifest:
    directories: tuple
    files: tuple

    @property
    def digest(self):
        return _hash({"domain": "mrk-git-init-candidate/1", "directories": self.directories,
                      "files": tuple((name, stamp.identity, stamp.digest) for name, stamp, _ in self.files)})

    def file(self, name):
        return next((stamp, body) for key, stamp, body in self.files if key == name)


def manifest(candidate, *, published=False):
    _need(type(candidate) is BorrowedCandidate, "git-init-candidate")
    candidate.check(published=published)
    root = candidate.root.path / ".git" if published else candidate.git.path
    directories, files = [], []
    # The exact finite roster is known from the fixed empty-template init.
    # Do not adopt an arbitrary stock/user-created tree after a failed command.
    for name in DIRECTORIES:
        path = root / name
        before = directory(path.lstat())
        _need(before[3] == candidate.root.identity[3] and before[0] == candidate.root.identity[0])
        expected = {Path(value).name for value in (*DIRECTORIES, *FILES)
                    if value and str(Path(value).parent) == (name or ".")}
        _need(set(names(path)) == expected, "git-init-candidate")
        _need(directory(path.lstat()) == before, "stale-observation")
        directories.append((name, before))
    for name, bound in (("HEAD", 64), ("config", MAX_CONFIG)):
        path = root / name
        info = path.lstat()
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == candidate.root.identity[3]
              and info.st_nlink == 1 and not info.st_mode & 0o7022
              and getattr(info, "st_flags", 0) == 0, "git-init-candidate")
        stamp, body = core._read(path, bound)
        _need(stamp.kind == "file" and core._identity(info) == stamp.identity, "stale-observation")
        files.append((name, stamp, body))
    result = Manifest(tuple(directories), tuple(files))
    _need(result.file("HEAD")[1] == b"ref: refs/heads/main\n", "git-init-candidate")
    candidate.check(published=published)
    return result


def configuration(raw):
    value = read._configuration(raw)
    required = {"core.repositoryformatversion": (b"0",), "core.bare": (b"false",),
                "core.logallrefupdates": (b"true",)}
    optional = {"core.filemode", "core.ignorecase", "core.precomposeunicode"}
    _need(all(value.get(name) == body for name, body in required.items())
          and "core.filemode" in value and set(value) <= set(required) | optional
          and all(value[name] in ((b"true",), (b"false",)) for name in optional if name in value),
          "git-init-candidate")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class InitIntent:
    expected_revision: str
    candidate_manifest: str
    candidate_head: str
    candidate_config: str
    action: str = field(default=ACTION, init=False)

    def as_dict(self):
        return {"action": ACTION, "expectedRevision": self.expected_revision,
                "initialBranch": BRANCH, "objectFormat": OBJECT_FORMAT,
                "candidateManifest": self.candidate_manifest,
                "candidateHead": self.candidate_head, "candidateConfig": self.candidate_config}


class InitSession(core._Session):
    """Fixed-command facet of the existing session/run_owned owner."""
    def __init__(self, repository, candidate):
        super().__init__(repository)
        self.deadline = min(self.deadline, repository.work_end)
        self.candidate = candidate
        self.generated = self.queried = False

    def command_spec(self, args):
        work = self.candidate.worktree.path
        init = ["init", "--quiet", "--initial-branch=main", "--object-format=sha1",
                "--template=" + str(self.candidate.template.path)]
        query = ["config", "--file", str(self.candidate.git.path / "config"),
                 "--no-includes", "--null", "--list"]
        _need(args == (query if self.generated else init) and not self.queried, "invalid-input")
        argv = [str(self.repository.git_executable), "--no-pager", "--no-replace-objects",
                "-c", "core.hooksPath=" + os.devnull, "-c", "protocol.allow=never",
                "-c", "maintenance.auto=false", "-c", "gc.auto=0", *args]
        # No GIT_DIR/worktree override, identity, external config or inherited
        # environment. Ordinary init writes a relocatable .git at this cwd.
        environ = {"PATH": os.defpath, "HOME": str(self.candidate.template.path),
                   "LANG": "C", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
                   "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
                   "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "",
                   "GIT_ATTR_NOSYSTEM": "1", "GIT_PAGER": "cat"}
        return argv, environ, work

    def execute(self, args, maximum):
        self.repository._current()
        remaining = self.deadline - time.monotonic()
        _need(self.calls < 2 and remaining >= 1, "deadline")
        self.calls += 1
        argv, environ, cwd = self.command_spec(args)
        result = self.repository._run(argv, cwd=cwd, environ=environ, capture=True, text=False,
            timeout=min(10, math.floor(remaining)), output_limit=maximum,
            cancellation=self.repository.cancellation, execution_scope=None)
        _need(result.args == argv and type(result.returncode) is int and result.returncode == 0
              and type(result.stdout) is bytes and len(result.stdout) <= maximum
              and type(result.stderr) is bytes and result.stderr == b"", "command-failed")
        if not self.generated:
            _need(result.stdout == b"", "response-invalid")
            self.generated = True
        else:
            self.queried = True
        self.repository._current()
        return result.stdout


class InitTransaction:
    def __init__(self, session, plan, owner):
        self.session, self.plan, self.owner = session, plan, owner
        self.candidate = session.candidate
        self.captured = self.intent = None
        self.acknowledged = self.attempted = self.returned = self.fsynced = False

    def publish(self):
        self.captured = manifest(self.candidate)
        self.intent = InitIntent(self.plan.expected_revision, self.captured.digest,
                                self.captured.file("HEAD")[0].digest, self.captured.file("config")[0].digest)
        self.owner.record_intent(self.intent)  # Original durable Candidate ACK.
        self.acknowledged = True
        self.session.repository._current()
        _need(manifest(self.candidate) == self.captured, "stale-observation")
        self.candidate.check()
        rename = _rename_function()  # Existing no-replace platform primitive.
        self.attempted = True  # Lost return is never inferred from path absence.
        rename(self.candidate.worktree.fd, b".git", self.candidate.root.fd, b".git")
        self.returned = True  # Root the actual result before fsync/checkpoints.
        os.fsync(self.candidate.root.fd)
        os.fsync(self.candidate.worktree.fd)
        self.fsynced = True
        _need(manifest(self.candidate, published=True) == self.captured, "recovery-required")
        self.session.repository._current()


class GitInitRepository(core.GitRepository):
    def __init__(self, root, *, git_executable, work_end, tool_digest, candidate=None, cancellation=None, _run=core.run_owned):
        super().__init__(root, git_executable=git_executable, cancellation=cancellation, _run=_run)
        _need(type(work_end) in (int, float) and math.isfinite(work_end)
              and type(tool_digest) is str and core._REVISION.fullmatch(tool_digest), "invalid-input")
        self.work_end, self.tool_digest, self.candidate = work_end, tool_digest, candidate
        self._transaction = self._active_plan = self._owner = None

    def _current(self):
        _need(time.monotonic() < self.work_end, "deadline")
        if self.cancellation is not None:
            self.cancellation.check()
        if self._owner is not None:
            self._owner.check_current(self.root, ACTION, self._active_plan.expected_revision)
        if self._transaction is not None and self._transaction.returned:
            self.candidate.check(published=True)
        else:
            captured = absence(self.root, self.candidate)
            if self._active_plan is not None:
                _need(captured == self._active_plan._absence, "stale-observation")

    @core._session_boundary
    def prepare_init(self):
        _need(not self._unknown and self._transaction is None and not self._retained, "recovery-required")
        self._current()
        captured = absence(self.root, self.candidate)
        revision = _hash({"domain": "mrk-git-init-source/1", "absence": captured, "tool": self.tool_digest})
        plan = InitPlan(revision, self._key, captured)
        return InitReview(plan, review_digest(plan))

    @core._session_boundary
    def apply_init(self, review, owner, *, expected_digest):
        _need(type(review) is InitReview and review.plan._key is self._key
              and not review.plan._used and review.digest == expected_digest == review_digest(review.plan)
              and self._transaction is None and type(self.candidate) is BorrowedCandidate, "authorization")
        review.plan._used = True
        self._active_plan, self._owner = review.plan, owner
        self._current()
        _need(names(self.candidate.git.path) == (), "git-init-candidate")
        session = InitSession(self, self.candidate)
        self._active_sessions.append(session)  # Before the first command.
        transaction = self._transaction = InitTransaction(session, review.plan, owner)
        try:
            session.execute(["init", "--quiet", "--initial-branch=main", "--object-format=sha1",
                             "--template=" + str(self.candidate.template.path)], 1024)
            before = manifest(self.candidate)
            configuration(session.execute(["config", "--file", str(self.candidate.git.path / "config"),
                                            "--no-includes", "--null", "--list"], MAX_CONFIG))
            _need(manifest(self.candidate) == before, "stale-observation")
            transaction.publish()
            return core.MutationResult(owner.operation_id, ACTION, "succeeded", "settled", None, None, transaction.intent)
        except BaseException:
            # No cleanup retry or metadata rollback. The original worker/native
            # source owner retains/settles its exact originals and journal.
            if transaction.attempted and not transaction.returned:
                self._unknown = True
            raise
