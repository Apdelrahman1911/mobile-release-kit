"""Bounded content-only local switch through the original GitLocal owners.

Only an existing local branch with the SAME tracked regular-file path/mode
roster is supported. Tracked contents and index must be clean. At most eight
files change; unrelated ignored/untracked entries are never destinations.
Git operates on a private index/ref/config view, not around the original Git
locks. No force, reset, stash, remote, hook/filter invocation or config rewrite.

This core does not admit a native invocation. The installed caller still owns
the original publisher, Preparing row, candidate ACK, source descriptors and
C/A/W lifetime. Matching bytes, a returned checkout or any receipt below is
NOT native finality. Partial effects are preserved, never rolled back/retried.
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

from . import git_repository_branches as branches
from . import git_repository_local as local
from . import git_repository_read as read
from . import git_service as core
from .owned_process import ProcessError

MAX_TRACKED = 256
MAX_CHANGED = 8
MAX_BYTES = 8 * 1024 * 1024
MAX_INDEX = 1024 * 1024
MAX_LOG = 60 * 1024  # Leaves room in the original finite scratch's 64KiB file.
MAX_PARENTS = 256
MAX_PRESERVED = 512
ATTRIBUTES = ("filter", "text", "eol", "ident", "working-tree-encoding")
_MESSAGE = "MRK: switch to reviewed local branch"
_LFS = b"version https://git-lfs.github.com/spec/v1\n"
_REASONS = frozenset(("switch-dirty", "switch-layout", "switch-target", "switch-conversion",
                      "switch-identity-required", "switch-log-limit", "switch-file-mode"))


class SwitchError(core.GitError):
    """Fixed actionable refusal; never includes repository or command text."""
    def __init__(self, reason: str):
        core._need(reason in _REASONS, "invalid-input")
        super().__init__("invalid-input")
        self.reason = reason


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise SwitchError(reason)


def _hash(value) -> str:
    return core._digest(json.dumps(value, ensure_ascii=True, sort_keys=True,
                                   separators=(",", ":")).encode("ascii"))


def _blob(raw: bytes, oid: str) -> str:
    core._need(core._OID.fullmatch(oid) is not None, "response-invalid")
    method = hashlib.sha1 if len(oid) == 40 else hashlib.sha256
    return method(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


@dataclass(frozen=True, slots=True)
class TreeFile:
    path: str
    mode: str
    oid: str
    size: int


def _tree(raw: bytes) -> tuple[TreeFile, ...]:
    """Parse only Git's fixed ls-tree -r -l -z format; not an object reader."""
    core._need(type(raw) is bytes and len(raw) <= 384 * 1024, "limit")
    result = []
    for row in core._nul(raw):
        fields, separator, name = row.partition(b"\t")
        parts = fields.split()
        core._need(separator == b"\t" and len(parts) == 4, "response-invalid")
        _require(parts[0] in (b"100644", b"100755") and parts[1] == b"blob", "switch-layout")
        core._need(re.fullmatch(rb"0|[1-9][0-9]{0,7}", parts[3]) is not None, "response-invalid")
        path, oid = core._decode_path(name), core._oid(parts[2])
        core._need(core._SECRET.search(name) is None, "sensitive-content")
        core._need(len(path.split("/")) <= read.MAX_REF_DEPTH, "unsupported-path")
        _require(".gitmodules" not in path.split("/"), "switch-layout")
        result.append(TreeFile(path, parts[0].decode("ascii"), oid, int(parts[3])))
        core._need(len(result) <= MAX_TRACKED and sum(item.size for item in result) <= MAX_BYTES, "limit")
    paths = [item.path for item in result]
    # Reuse the original pure portable-path validator, NOT its mutation owner.
    from .init_transaction import validate_paths
    try:
        if paths:
            validate_paths(paths)
    except Exception as error:
        from .errors import ValidationError
        if isinstance(error, ValidationError):
            raise SwitchError("switch-layout") from None
        raise
    core._need(len(set(paths)) == len(paths), "response-invalid")
    return tuple(sorted(result, key=lambda item: item.path))


def _flags(raw: bytes, paths: tuple[str, ...]) -> None:
    rows = core._nul(raw)
    _require(len(rows) == len(paths), "switch-dirty")
    actual = []
    for row in rows:
        _require(row[:2] == b"H ", "switch-dirty")  # No assume-unchanged/skip-worktree/unmerged entry.
        actual.append(core._decode_path(row[2:]))
    _require(tuple(sorted(actual)) == paths and len(set(actual)) == len(paths), "switch-dirty")


def _attributes(raw: bytes, paths: tuple[str, ...]) -> None:
    rows = core._nul(raw)
    core._need(len(rows) == len(paths) * len(ATTRIBUTES) * 3, "response-invalid")
    at = 0
    for path in paths:
        for attribute in ATTRIBUTES:
            name, key, value = rows[at:at + 3]
            at += 3
            core._need(core._decode_path(name) == path and key == attribute.encode("ascii"), "response-invalid")
            _require(value in (b"unspecified", b"unset"), "switch-conversion")


def _identity(config: dict) -> core.CommitIdentity:
    # Same source-backed local identity subset as branch creation. The tiny
    # default-preserving Root hook extracts it from that existing validator.
    validator = getattr(branches, "_local_identity", None)
    core._need(validator is not None, "authorization")
    try:
        return validator(config)
    except branches.BranchError:
        raise SwitchError("switch-identity-required") from None


def _directory(path: Path) -> tuple[int, ...]:
    info = path.lstat()
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
             and not info.st_mode & 0o7022, "switch-layout")
    return (*core._identity(info), info.st_uid, info.st_gid)


@dataclass(frozen=True, slots=True, repr=False)
class _Log:
    enabled: bool
    original: core._Stamp
    content: bytes
    parent: tuple[int, ...]
    identity: core.CommitIdentity

    def comparison(self):
        return (self.enabled, self.original.kind, self.original.identity, self.original.digest,
                self.parent, self.identity.name, self.identity.email)


def _logging(git: Path, config: dict) -> _Log:
    value = config.get("core.logallrefupdates", (b"true",))
    _require(value in ((b"true",), (b"false",)), "switch-layout")
    identity = _identity(config)
    # This profile creates no original log directories. Ordinary full repos
    # already have logs/ after their first commit; absent layouts use Git.
    try:
        parent = _directory(git / "logs")
        original, body = core._read(git / "logs/HEAD", MAX_LOG)
    except core.GitError as error:
        if error.reason == "limit":
            raise SwitchError("switch-log-limit") from None
        raise
    except FileNotFoundError:
        raise SwitchError("switch-layout") from None
    _require(original.kind in ("file", "absent"), "switch-layout")
    if body:
        _require(body.endswith(b"\n"), "switch-layout")
    return _Log(value == (b"true",) or original.kind == "file", original, body, parent, identity)


@dataclass(frozen=True, slots=True, repr=False)
class _Footprint:
    files: tuple[tuple[str, core._Stamp], ...]
    ancestors: tuple[tuple[str, tuple[int, ...]], ...]
    parents: tuple[tuple[str, tuple[int, ...]], ...]
    preserved: tuple[tuple[str, core._Stamp], ...]

    def comparison(self):
        stamps = lambda rows: [(name, stamp.kind, stamp.identity, stamp.digest) for name, stamp in rows]
        return (stamps(self.files), self.ancestors, self.parents, stamps(self.preserved))


def _stamp_preserved(path: Path, maximum: int) -> tuple[core._Stamp, int]:
    stamp, raw = core._read(path, maximum, regular=False)
    _require(stamp.kind in ("file", "directory", "symlink"), "switch-layout")
    if stamp.kind == "symlink":
        raw = os.fsencode(os.readlink(path))
        core._need(len(raw) <= 4096 and core._read(path, maximum, regular=False)[0] == stamp, "stale-observation")
        stamp = core._Stamp(stamp.kind, stamp.identity, core._digest(raw))
    return stamp, len(raw)


def _footprint(session, tree: tuple[TreeFile, ...], changed: tuple[str, ...]) -> _Footprint:
    files, parents, preserved, used = [], {}, {}, 0
    ancestors = {".": _directory(session.root)}
    for item in tree:
        session.guard_current()
        path = session.root / item.path
        current = session.root
        for component in item.path.split("/")[:-1]:
            current /= component
            ancestors[str(current.relative_to(session.root))] = _directory(current)
            core._need(len(ancestors) <= MAX_PARENTS, "limit")
            _require(core._read(current / ".git", 2048, regular=False)[0].kind == "absent", "switch-layout")
        stamp, raw = core._read(path, min(core.MAX_FILE_BYTES, MAX_BYTES - used))
        _require(stamp.kind == "file" and len(raw) == item.size and _blob(raw, item.oid) == item.oid,
                 "switch-dirty")
        info = path.lstat()
        _require(info.st_uid == os.getuid() and info.st_nlink == 1 and not info.st_mode & 0o7022
                 and ("100755" if info.st_mode & 0o111 else "100644") == item.mode, "switch-layout")
        if item.path in changed:
            # Stock checkout derives ordinary 0644/0755 from its existing
            # process umask. The transaction probes its read/write mask first
            # and still checks exact final modes. Never broaden a 0600 file.
            _require(stat.S_IMODE(info.st_mode) == (0o755 if item.mode == "100755" else 0o644), "switch-layout")
        _require(not raw.startswith(_LFS), "switch-conversion")
        if item.path in changed:
            core._need(not core._sensitive_path(item.path) and core._SECRET.search(raw) is None, "sensitive-content")
        used += len(raw)
        files.append((item.path, stamp))
    # Only parents Git may touch are censused. All existing direct children
    # outside changed destinations remain exact. Unvisited subtrees cannot be
    # destinations in the identical tracked path/mode scope.
    for name in changed:
        current = (session.root / name).parent
        while current.is_relative_to(session.root):
            relative = str(current.relative_to(session.root))
            parents[relative] = _directory(current)
            if current == session.root:
                break
            current = current.parent
    core._need(len(parents) <= MAX_PARENTS, "limit")
    tracked = dict(files)
    for name, before in sorted(parents.items()):
        path = session.root / name
        for child in session.names(path):
            selected = str((path / child).relative_to(session.root))
            if selected == ".git" or selected in changed or selected in parents:
                continue
            if selected in tracked:
                stamp = tracked[selected]
            else:
                stamp, size = _stamp_preserved(path / child, min(core.MAX_FILE_BYTES, MAX_BYTES - used))
                used += size
            preserved[selected] = stamp
            core._need(len(preserved) <= MAX_PRESERVED and used <= MAX_BYTES, "limit")
        core._need(_directory(path) == before, "stale-observation")
    return _Footprint(tuple(files), tuple(sorted(ancestors.items())), tuple(sorted(parents.items())), tuple(sorted(preserved.items())))


@dataclass(slots=True, repr=False)
class SwitchPlan:
    name: str
    target_oid: str
    reference_revision: str
    source_tree: tuple[TreeFile, ...]
    target_tree: tuple[TreeFile, ...]
    changed: tuple[str, ...]
    _key: object
    _snapshot: core._Snapshot
    _footprint: _Footprint
    _log: _Log
    _target_hashes: tuple[tuple[str, str], ...]
    _used: bool = False
    action: str = field(default="branch-switch", init=False)

    @property
    def target(self) -> str:
        return "refs/heads/" + self.name

    def public(self):
        source = self._snapshot.public
        before = {f.path: f for f in self.source_tree}
        after = {f.path: f for f in self.target_tree}
        stamps = dict(self._footprint.files)
        target_hashes = dict(self._target_hashes)
        return {"action": self.action, "name": self.name, "targetRef": self.target, "targetOid": self.target_oid,
                "expectedRevision": source.revision, "expectedReferenceRevision": self.reference_revision,
                "head": source.head, "branch": source.branch, "expectedIndex": self._snapshot.index_stamp.digest,
                "paths": list(self.changed), "trackedCount": len(self.source_tree), "contentOnly": True,
                "files": [{"path": p, "mode": after[p].mode, "sourceOid": before[p].oid,
                    "targetOid": after[p].oid, "sourceSha256": stamps[p].digest,
                    "targetSha256": target_hashes[p], "targetSize": after[p].size} for p in self.changed],
                "log": {"enabled": self._log.enabled, "originalKind": self._log.original.kind,
                        "originalSha256": self._log.original.digest}}


def _review_digest(plan: SwitchPlan) -> str:
    return core._digest(b"mrk-git-content-switch-review/1\0" + _hash({"review": plan.public(),
        "trees": [[(f.path, f.mode, f.oid, f.size) for f in tree] for tree in (plan.source_tree, plan.target_tree)],
        "footprint": plan._footprint.comparison(), "log": plan._log.comparison(),
        "attributes": [(str(p), s.kind, s.identity, s.digest) for p, s in sorted(plan._snapshot.metadata.items())]
        }).encode("ascii"))


@dataclass(frozen=True, slots=True, repr=False)
class SwitchReview:
    plan: SwitchPlan
    digest: str

    def as_dict(self):
        return {**self.plan.public(), "reviewDigest": self.digest}


@dataclass(frozen=True, slots=True, repr=False)
class SwitchIntent:
    expected_revision: str
    expected_reference_revision: str
    expected_ref: str
    expected_head: str
    expected_index: str
    target_ref: str
    target_oid: str
    candidate_index: str
    original_head: str
    candidate_head: str
    original_log: str
    candidate_log: str
    log_enabled: bool
    footprint: str
    action: str = field(default="branch-switch", init=False)

    def as_dict(self):
        return {"action": self.action, "expectedRevision": self.expected_revision,
                "expectedReferenceRevision": self.expected_reference_revision,
                "expectedRef": self.expected_ref, "expectedHead": self.expected_head,
                "expectedIndex": self.expected_index, "targetRef": self.target_ref, "targetOid": self.target_oid,
                "candidateIndex": self.candidate_index, "originalHead": self.original_head,
                "candidateHead": self.candidate_head, "originalLog": self.original_log,
                "candidateLog": self.candidate_log, "logEnabled": self.log_enabled, "footprint": self.footprint}


class _SwitchSession(branches._BranchSession):
    def __init__(self, repository):
        super().__init__(repository)
        self.switch_plan = None
        self.exec_view = None
        self.execution_command = None
        self.switch_successors = {}
        self.target_lock = repository._target_lock

    def guard_current(self):
        self.checkpoint()
        owner = self.repository._active_owner
        revision = self.repository._apply_expected_revision
        if revision is not None:
            core._need(owner is not None, "authorization")
            owner.check_current(self.root, "branch-switch", revision)
        self.checkpoint()

    def discover(self):
        super().discover()
        if self.target_lock is not None:
            self.originals = self.target_lock.comparison(self.originals)

    def _hooks(self):
        rows = list(super()._hooks())
        if rows == [("hooks", None)]:
            return tuple(rows)
        path = self.git_dir / "hooks/post-checkout"
        try:
            info = path.lstat()
        except FileNotFoundError:
            rows.append(("hooks/post-checkout", None))
        else:
            core._need(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o111, "required-hooks")
            rows.append(("hooks/post-checkout", core._identity(info)))
        return tuple(rows)

    def names(self, path):
        result = super().names(path)
        lock = self.target_lock
        if lock is not None and path == lock.path.parent:
            lock.check()
            core._need(lock.path.name in result, "stale-observation")
            return tuple(name for name in result if name != lock.path.name)
        return result

    def check_original(self):
        if self.target_lock is not None:
            self.target_lock.check()
        current = read._inventory(self.git_dir, self.checkpoint, self.names)
        original = self.originals
        if self.target_lock is not None:
            current = self.target_lock.comparison(current)
            original = self.target_lock.comparison(original)
        files = tuple((name, *self.switch_successors[name]) if name in self.switch_successors else (name, stamp, raw)
                      for name, stamp, raw in original.files)
        expected = read._ReferenceInventory(original.directories, files, original.forbidden, original.pack)
        hooks = self._hooks()
        if self.hooks is None:
            self.hooks = hooks
        core._need(current == expected and self.hooks == hooks, "stale-observation")
        self.check_object_parents()

    def command_spec(self, args, *, index=None, identity=None):
        extra = (args == ["ls-files", "-v", "-z"] or args[:3] == ["ls-tree", "-r", "-l"]
                 and len(args) == 5 and args[3] == "-z" and core._OID.fullmatch(args[4]) is not None
                 or args[:3] == ["check-attr", "--cached", "-z"] and args[3:8] == list(ATTRIBUTES)
                 and args[8:9] == ["--"] and len(args[9:]) <= MAX_TRACKED
                 or args[:2] == ["check-attr", "-z"] and args[2:7] == list(ATTRIBUTES)
                 and args[7:8] == ["--"] and len(args[8:]) <= MAX_TRACKED)
        transaction = self.repository._transaction
        if self.execution_command is not None:
            core._need(transaction is not None and transaction.session is self
                       and (tuple(args), index, identity) == self.execution_command, "authorization")
            transaction.check_original()
            seed = ["ls-files", "--stage", "-z"]
            argv, environment = read._ReadSession.command_spec(self, seed)
            argv = [*argv[:-len(seed)], *args]
            argv[argv.index("--git-dir=" + str(self.frozen.root))] = "--git-dir=" + str(self.exec_view.root)
            environment.update(GIT_INDEX_FILE=str(index), HOME=str(self.exec_view.root),
                               XDG_CONFIG_HOME=str(self.exec_view.root))
            if identity is not None:
                core._need(identity is transaction.plan._log.identity, "authorization")
                environment.update(GIT_COMMITTER_NAME=identity.name, GIT_COMMITTER_EMAIL=identity.email,
                                   GIT_AUTHOR_NAME=identity.name, GIT_AUTHOR_EMAIL=identity.email)
            return argv, environment
        if extra:
            core._need(index is None and identity is None, "invalid-input")
            seed = ["ls-files", "--stage", "-z"]
            argv, environment = read._ReadSession.command_spec(self, seed)
            return [*argv[:-len(seed)], *args], environment
        return super().command_spec(args, index=index, identity=identity)

    def execute_private(self, args, *, index, identity=None):
        """Only the finite transaction calls this after retaining exact phase.

        No stdin or arbitrary public role; command_spec also rematches the
        actual transaction immediately before the original worker's spawn.
        """
        transaction = self.repository._transaction
        core._need(transaction is not None and transaction.session is self and self.execution_command is None,
                   "authorization")
        transaction.admit_command(args, index, identity)
        self.execution_command = (tuple(args), index, identity)
        try:
            # The same command/deadline/C/A/W call path as existing local work.
            return self.git(args, index=index, identity=identity,
                            limit=384 * 1024 if args == ["ls-files", "--stage", "-z"] else 4096)
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
        core._need(self.calls <= core.MAX_CALLS and 0 < limit <= core.MAX_GIT_BYTES, "limit")
        core._need(remaining >= 1, "deadline")
        result = self.repository._run(argv, cwd=self.frozen.root, environ=environment, capture=True, text=False,
            timeout=min(10, math.floor(remaining)), output_limit=limit,
            cancellation=self.repository.cancellation, execution_scope=None)
        core._need(result.args == argv and type(result.returncode) is int and type(result.stdout) is bytes
                   and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= limit,
                   "response-invalid")
        core._need(result.returncode == 0, "command-failed")
        # Production performs this same closed hook inside command(), after
        # actual C/A/W return and BEFORE its source postcheck. Core fixtures
        # have no native source owner; do not mint a second receipt there.
        if transaction.command_entered is not None:
            transaction.command_did_return(args, result)
        self.guard_current()
        return result.returncode, result.stdout


class GitSwitchRepository(branches.GitBranchesRepository):
    """Closed facade; original MutationOwner and target-lock owner required."""
    def __init__(self, *args, _target_lock=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._target_lock = _target_lock
        self._apply_expected_revision = None

    def _session(self):
        core._need(not self._unknown, "unknown")
        session = _SwitchSession(self)
        self._active_sessions.append(session)
        session.discover()
        return session

    def _capture_switch(self, session, name, expected_revision, expected_reference_revision):
        name = branches.branch_name(name)
        core._need(type(expected_reference_revision) is str and core._REVISION.fullmatch(expected_reference_revision),
                   "invalid-input")
        before = session.snapshot()
        self._expected(before, expected_revision)
        core._need(session.reference_revision(before.public) == expected_reference_revision, "stale-observation")
        self._policy(before, "branch-switch")
        core._need("required-signing" not in before.public.restrictions, "required-signing")
        _require(before.public.head is not None and before.public.branch is not None, "switch-layout")
        _require(before.index_stamp.kind == "file" and len(before.index_bytes) <= MAX_INDEX, "switch-layout")
        _require(not any(row.index not in ("?", "!") or row.worktree not in ("?", "!")
                         for row in before.public.changes), "switch-dirty")
        _require(before.config.get("core.autocrlf", (b"false",)) == (b"false",)
                 and not any(key.startswith("checkout.") for key in before.config), "switch-conversion")
        _require(before.config.get("core.sharedrepository", (b"false",)) in ((b"false",), (b"0",)), "switch-layout")
        for fixed in ("worktrees", "info/sparse-checkout"):
            _require(core._read(session.git_dir / fixed, 65536, regular=False)[0].kind == "absent", "switch-layout")
        target = "refs/heads/" + name
        rows = session.catalog()
        matches = [row for row in rows if row.ref == target]
        _require(len(matches) == 1 and target != before.public.branch, "switch-target")
        session.require_ref_parent(target)
        target_oid = matches[0].oid
        _, source_raw = session.git(["ls-tree", "-r", "-l", "-z", before.public.head], limit=384 * 1024)
        source_tree = _tree(source_raw)
        if target_oid == before.public.head:
            target_tree = source_tree
        else:
            _, target_raw = session.git(["ls-tree", "-r", "-l", "-z", target_oid], limit=384 * 1024)
            target_tree = _tree(target_raw)
        _require([(item.path, item.mode) for item in source_tree] == [(item.path, item.mode) for item in target_tree],
                 "switch-layout")
        _require(before.entries == {item.path: (core._Entry(item.mode, item.oid, 0),) for item in source_tree},
                 "switch-dirty")
        paths = tuple(item.path for item in source_tree)
        changed = tuple(before.path for before, after in zip(source_tree, target_tree) if before.oid != after.oid)
        core._need(len(changed) <= MAX_CHANGED, "limit")
        _require(all(Path(path).name != ".gitattributes" for path in changed), "switch-layout")
        footprint = _footprint(session, source_tree, changed)
        # Attribute files may be untracked. Bind every applicable existing
        # parent before querying them; the execution view later has a fixed
        # highest-priority no-conversion rule, only after this policy refuses
        # any actually requested transform. A racing policy cannot execute.
        attribute_paths = {session.git_dir / "info/attributes", session.root / ".gitattributes"}
        for path in paths:
            for parent in (session.root / path).parents:
                if not parent.is_relative_to(session.root):
                    break
                attribute_paths.add(parent / ".gitattributes")
        core._need(len(attribute_paths) <= MAX_PARENTS + 2, "limit")
        for path in sorted(attribute_paths):
            before.metadata[path] = core._read(path, 65536)[0]
        _, flags = session.git(["ls-files", "-v", "-z"], limit=384 * 1024)
        _flags(flags, paths)
        if paths:
            _, attributes = session.git(["check-attr", "--cached", "-z", *ATTRIBUTES, "--", *paths], limit=384 * 1024)
            _attributes(attributes, paths)
            _, attributes = session.git(["check-attr", "-z", *ATTRIBUTES, "--", *paths], limit=384 * 1024)
            _attributes(attributes, paths)
        source_paths = set(paths)
        used = sum(item.size for item in source_tree) + sum(
            s.identity[3] for p, s in footprint.preserved if p not in source_paths and s.kind == "file")
        hashes = []
        for item in target_tree:
            if item.path not in changed:
                continue
            core._need(used + item.size <= MAX_BYTES, "limit")
            _, raw = session.git(["cat-file", "blob", item.oid], limit=max(1024, min(core.MAX_FILE_BYTES, item.size + 1)))
            core._need(len(raw) == item.size and _blob(raw, item.oid) == item.oid, "response-invalid")
            _require(not raw.startswith(_LFS), "switch-conversion")
            core._need(core._SECRET.search(raw) is None, "sensitive-content")
            used += len(raw)
            hashes.append((item.path, core._digest(raw)))
        logging = _logging(session.git_dir, before.config)
        plan = SwitchPlan(name, target_oid, expected_reference_revision, source_tree, target_tree,
                          changed, self._key, before, footprint, logging, tuple(hashes))
        session.switch_plan = plan
        session.check_original()
        session._check_frozen()
        core._need(all(core._read(p, 65536)[0] == s for p, s in before.metadata.items()), "stale-observation")
        return plan

    @core._session_boundary
    def prepare_switch(self, name, *, expected_revision, expected_reference_revision):
        core._need(not self._retained and not self._apply_entered, "recovery-required")
        plan = self._capture_switch(self._session(), name, expected_revision, expected_reference_revision)
        return SwitchReview(plan, _review_digest(plan))

    @core._session_boundary
    def apply_switch(self, review: SwitchReview, owner: core.MutationOwner, *, expected_digest: str):
        core._need(type(review) is SwitchReview and type(review.plan) is SwitchPlan and review.plan._key is self._key
                   and not review.plan._used and not self._apply_entered and not self._retained, "already-used")
        core._need(review.digest == expected_digest == _review_digest(review.plan), "stale-observation")
        self._apply_entered = True
        session = self._session()
        current = self._capture_switch(session, review.plan.name, review.plan._snapshot.public.revision,
                                       review.plan.reference_revision)
        core._need(_review_digest(current) == review.digest, "stale-observation")
        review.plan._used = True
        return self._apply_captured(session, SwitchReview(current, review.digest), owner)

    def _apply_captured(self, session, review, owner):
        """The worker's SAME fresh Apply capture; not a wire-plan constructor.

        The fixed worker can call this after its one fresh _capture_switch and
        exact native retained-review comparison, avoiding a second complete
        prepare. It must already own the one Apply latch/session. No public
        endpoint can supply this original session/plan or MutationOwner.
        """
        from .git_switch_transaction import BorrowedTargetLock, Handoff, SwitchTransaction, TargetLock
        core._need(self._apply_entered and len(self._active_sessions) == 1 and self._active_sessions[0] is session
                   and type(session) is _SwitchSession and session.repository is self and self._transaction is None
                   and type(review) is SwitchReview and review.plan._key is self._key
                   and review.digest == _review_digest(review.plan), "authorization")
        plan = review.plan
        handoff = Handoff(self, plan._snapshot.public.revision, owner)
        self._active_plan, self._active_owner = plan, handoff
        self._apply_expected_revision = plan._snapshot.public.revision
        transaction = None
        intent = observation = reason = None
        state, settlement = "failed", "settled"
        try:
            handoff.check_current(self.root, plan.action, plan._snapshot.public.revision)
            if self._target_lock is None:
                self._target_lock = session.target_lock = TargetLock(self.root, plan.target)
                self._target_lock.acquire()
            else:
                core._need(type(self._target_lock) is BorrowedTargetLock and self._target_lock.target == plan.target,
                           "authorization")
                self._target_lock.check()
            session.originals = self._target_lock.comparison(session.originals)
            transaction = self._transaction = SwitchTransaction(session, plan._snapshot, plan, handoff)
            transaction.acquire()
            transaction.prepare_candidates()
            intent = transaction.intent
            handoff.record_intent(intent)
            transaction.check_original()
            transaction.checkout()
            names = ("logs/HEAD", "HEAD", "index") if plan._log.enabled else ("HEAD", "index")
            for name in names:
                transaction.publish_metadata(name)
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
                transaction.retained = True
                self._retained.append(transaction)
            raise
        finally:
            if not self._unknown:
                self._active_plan = self._active_owner = self._apply_expected_revision = None
        return core.MutationResult(handoff.operation_id, plan.action, state, settlement, reason, observation, intent)

    def _finish_sessions(self, uncertain):
        from .git_switch_transaction import TargetLock
        good = super()._finish_sessions(uncertain)
        # Native-held locks are NOT closed by Python. Actual local fixture
        # locks retire only after this core's original source views returned.
        if good and type(self._target_lock) is TargetLock:
            try:
                good = self._target_lock.close()
            except BaseException:
                self._unknown = True
                raise
            if not good:
                self._unknown = True
        return good

    def _refuse_other_write(self, *args, **kwargs):
        raise core.GitError("invalid-input")

    prepare_branch = apply_branch = _refuse_other_write
