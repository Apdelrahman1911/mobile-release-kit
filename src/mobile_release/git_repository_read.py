"""Closed read-only repository facet; never a native admission or Git writer.

The installed caller must retain its actual project/tool/process originals.
Every command uses a private, finite config/ref view, including the first
``config --file --no-includes`` census. Original configuration is never loaded
as executable Git configuration. Git itself resolves the copied standard refs;
this module neither implements ref resolution nor obtains remote/provider state.

The ordinary Git service's revision, diff policy and mutation behavior are not
changed. Its diff sensitivity checks are bounded heuristics, NOT a guarantee
that arbitrary repository text contains no secrets. History deliberately omits
messages, signatures, authors and email addresses.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
from typing import Any

from . import git_service as core

MAX_LOOSE_REFS = 256
MAX_REF_DIRECTORIES = 256
MAX_PACKED_REFS_BYTES = 65536
MAX_REF_DEPTH = 32
MAX_WALK = 10000
HISTORY_COUNT = 25
MAX_HISTORY_BYTES = 64 * 1024
_FORMAT = "%(refname)%00%(upstream)%00%(upstream:remotename)%00%(upstream:remoteref)%00"
_VERSION = re.compile(rb"git version 2\.([0-9]{1,3})\.([0-9]{1,3})(?: \(Apple Git-[0-9]{1,6}\))?\n\Z")
_FORBIDDEN_LAYOUT = ("commondir", "gitdir", "config.worktree", "objects/info/alternates",
                     "objects/info/http-alternates", "info/grafts", "reftable")
_CONFIG_FILE = "mrk-read-original-config"


def _full_ref(value: str) -> bool:
    try:
        return (type(value) is str and value.startswith("refs/")
                and core._ref("refs/heads/" + value[5:]))
    except UnicodeError:
        return False


def _decoded(value: bytes, limit: int = 1024) -> str:
    try:
        return core._text(value.decode("utf-8", "strict"), limit)
    except UnicodeError:
        raise core.GitError("unsupported-repository") from None


def _config_key(value: bytes) -> str:
    # Git sections/variable names are case-insensitive, subsections are NOT.
    # In particular Origin and origin (or Main and main) are distinct refs.
    key = _decoded(value)
    parts = key.split(".")
    core._need(len(parts) >= 2 and all(parts), "unsupported-repository")
    return ".".join((parts[0].lower(), *parts[1:-1], parts[-1].lower()))


def _configuration(raw: bytes) -> dict[str, tuple[bytes, ...]]:
    config: dict[str, tuple[bytes, ...]] = {}
    for row in core._nul(raw):
        key, separator, value = row.partition(b"\n")
        core._need(separator == b"\n", "unsupported-repository")
        name = _config_key(key)
        core._need(name != "include.path" and not name.startswith("includeif."), "unsupported-repository")
        core._need(not name.startswith("filter."), "unsupported-filter")
        core._need(name not in ("core.worktree", "core.attributesfile", "core.excludesfile",
                                "core.checkroundtripencoding"), "unsupported-repository")
        core._need(not name.startswith("extensions.") or name in
                   ("extensions.objectformat", "extensions.worktreeconfig"), "unsupported-repository")
        core._need(not (name.startswith("remote.") and name.endswith((".promisor", ".partialclonefilter"))),
                   "unsupported-repository")
        config[name] = (*config.get(name, ()), value)
    core._need(config.get("extensions.worktreeconfig", (b"false",)) == (b"false",), "unsupported-repository")
    core._need(config.get("core.bare", (b"false",)) == (b"false",), "unsupported-repository")
    core._need(config.get("extensions.objectformat", (b"sha1",)) in ((b"sha1",), (b"sha256",)),
               "unsupported-repository")
    core._need(config.get("core.repositoryformatversion", (b"0",)) in ((b"0",), (b"1",)),
               "unsupported-repository")
    for name in ("core.sparsecheckout", "index.sparse", "core.splitindex"):
        core._need(config.get(name, (b"false",)) == (b"false",), "unsupported-repository")
    return config


def _quoted(raw: bytes) -> bytes:
    # Only Git's documented quoted-value escapes, not a shell serialization.
    core._need(all(c >= 32 and c != 127 or c in (9, 10) for c in raw), "unsupported-repository")
    return b'"' + raw.replace(b"\\", b"\\\\").replace(b'"', b'\\"').replace(b"\n", b"\\n").replace(b"\t", b"\\t") + b'"'


def _tracking_configuration(config: dict[str, tuple[bytes, ...]]) -> bytes:
    lines = []
    for key, values in sorted(config.items()):
        section, _, rest = key.partition(".")
        subsection, _, variable = rest.rpartition(".")
        if not subsection or not ((section == "branch" and variable in ("remote", "merge")) or
                                  (section == "remote" and variable in ("url", "fetch"))):
            continue
        # URL values remain private scratch only. No network/credential/helper
        # command exists; preserving them avoids inventing a surrogate remote.
        core._text(subsection, 1024)
        lines.append(b"[" + section.encode("ascii") + b" " + _quoted(subsection.encode("utf-8")) + b"]")
        lines.extend(variable.encode("ascii") + b" = " + _quoted(value) for value in values)
    result = b"\n".join(lines) + b"\n"
    core._need(len(result) <= 65536, "limit")
    return result


@dataclass(frozen=True, slots=True, repr=False)
class _ReferenceInventory:
    directories: tuple[tuple[str, tuple[int, ...]], ...]
    files: tuple[tuple[str, core._Stamp, bytes], ...]
    forbidden: tuple[tuple[str, core._Stamp], ...]
    pack: tuple[tuple[str, tuple[int, ...]], ...]

    def comparison(self) -> bytes:
        value = (self.directories, [(name, stamp.kind, stamp.identity, stamp.digest) for name, stamp, _ in self.files],
                 [(name, stamp.kind, stamp.identity, stamp.digest) for name, stamp in self.forbidden], self.pack)
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def body(self, name: str) -> bytes:
        return next(body for selected, _, body in self.files if selected == name)

    @property
    def shallow(self) -> bool:
        return next(stamp.kind != "absent" for name, stamp, _ in self.files if name == "shallow")


def _inventory(git_dir: Path, checkpoint, names) -> _ReferenceInventory:
    checkpoint()
    directories: list[tuple[str, tuple[int, ...]]] = []
    files: list[tuple[str, core._Stamp, bytes]] = []
    forbidden = []
    # Validate fixed parents before any child file lookup. In particular an
    # info-directory symlink must not redirect the config/attribute census.
    for name in ("objects", "objects/info", "objects/pack"):
        checkpoint()
        info = (git_dir / name).lstat()
        core._need(stat.S_ISDIR(info.st_mode), "unsupported-repository")
        directories.append((name, core._identity(info)))
    stamp, _ = core._read(git_dir / "info", 65536, regular=False)
    core._need(stamp.kind in ("absent", "directory"), "unsupported-repository")
    forbidden.append(("info", stamp))
    for name in _FORBIDDEN_LAYOUT:
        checkpoint()
        stamp, _ = core._read(git_dir / name, 65536, regular=False)
        core._need(stamp.kind == "absent", "unsupported-repository")
        forbidden.append((name, stamp))
    for name, required, limit in (("HEAD", True, 2048), ("config", True, 65536),
                                  ("packed-refs", False, MAX_PACKED_REFS_BYTES), ("shallow", False, 65536)):
        checkpoint()
        stamp, body = core._read(git_dir / name, limit)
        core._need(stamp.kind == "file" if required else stamp.kind in ("file", "absent"), "unsupported-repository")
        files.append((name, stamp, body))
    pending = ["refs"]
    loose = 0
    while pending:
        name = pending.pop(0)
        checkpoint()
        info = (git_dir / name).lstat()
        core._need(stat.S_ISDIR(info.st_mode), "unsupported-repository")
        directories.append((name, core._identity(info)))
        core._need(len(directories) <= MAX_REF_DIRECTORIES, "limit")
        for child in names(git_dir / name):
            path = name + "/" + child
            core._need(_full_ref(path) and len(path.split("/")) <= MAX_REF_DEPTH, "unsupported-repository")
            checkpoint()
            info = (git_dir / path).lstat()
            if stat.S_ISDIR(info.st_mode):
                core._need(len(pending) + len(directories) < MAX_REF_DIRECTORIES, "limit")
                pending.append(path)
            else:
                loose += 1
                core._need(loose <= MAX_LOOSE_REFS, "limit")
                stamp, body = core._read(git_dir / path, 2048)
                core._need(stamp.kind == "file", "unsupported-repository")
                files.append((path, stamp, body))
        checkpoint()
        core._need(core._identity((git_dir / name).lstat()) == directories[-1][1], "stale-observation")
    # Promisor packs are not a version-dependent GIT_NO_LAZY_FETCH promise.
    pack = []
    for name in names(git_dir / "objects/pack"):
        checkpoint()
        core._need(not name.endswith(".promisor"), "unsupported-repository")
        info = (git_dir / "objects/pack" / name).lstat()
        core._need(stat.S_ISREG(info.st_mode), "unsupported-repository")
        pack.append((name, core._identity(info)))
    return _ReferenceInventory(tuple(sorted(directories)), tuple(sorted(files)), tuple(forbidden), tuple(sorted(pack)))


def _read_arguments(args: list[str], config_path: Path) -> bool:
    """Closed syntax only; the original operation must also bind its sources."""
    if type(args) is not list or not args or any(type(arg) is not str for arg in args):
        return False
    try:
        if any(len(arg.encode("utf-8")) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in arg)
               for arg in args):
            return False
    except UnicodeError:
        return False
    fixed = (["config", "--file", str(config_path), "--no-includes", "--null", "--list"],
        ["--version"], ["rev-parse", "--shared-index-path"],
        ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"], ["ls-files", "--stage", "-z"],
        ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=all", "--no-renames"])
    if args in fixed:
        return True
    if len(args) == 3 and args[:2] == ["symbolic-ref", "--quiet"]:
        return args[2] == "HEAD" or core._ref(args[2])
    if len(args) == 4 and args[:3] == ["show-ref", "--verify", "--quiet"]:
        return core._ref(args[3])
    if len(args) == 5 and args[:4] == ["rev-parse", "--verify", "--quiet", "--end-of-options"]:
        return args[4].endswith("^{commit}") and _full_ref(args[4][:-9])
    if len(args) == 6 and args[:5] == ["for-each-ref", "--count=1", "--sort=refname", "--format=" + _FORMAT, "--"]:
        return core._ref(args[5])
    if len(args) == 6 and args[:4] == ["rev-list", "--left-right", "--count", "--max-count=" + str(MAX_WALK + 1)] and args[-1] == "--":
        pair = args[4].split("...")
        return len(pair) == 2 and all(core._OID.fullmatch(value) is not None for value in pair)
    if len(args) == 6 and args[:4] == ["rev-list", "--timestamp", "--parents", "--max-count=" + str(HISTORY_COUNT + 1)] and args[-1] == "--":
        return core._OID.fullmatch(args[4]) is not None
    prefix = ["diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames", "--src-prefix=a/", "--dst-prefix=b/"]
    tail = args[len(prefix):] if args[:len(prefix)] == prefix else []
    if tail[:1] == ["--cached"]:
        tail = tail[1:]
    if args[:4] == ["check-attr", "-z", "filter", "--"]:
        tail = ["--", *args[4:]]
    if tail[:1] != ["--"]:
        return False
    try:
        return tuple(tail[1:]) == core._paths(tail[1:])
    except core.GitError:
        return False


@dataclass(slots=True, repr=False)
class _Scan:
    iterator: Any = None
    entered: bool = False
    close_claimed: bool = False
    closed: bool = False


@dataclass(frozen=True, slots=True)
class Tracking:
    state: str
    remote: str | None = None
    merge_ref: str | None = None
    local_ref: str | None = None
    head: str | None = None
    ahead: int | None = None
    behind: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"state": self.state, "remote": self.remote, "mergeRef": self.merge_ref,
                "localRef": self.local_ref, "head": self.head, "ahead": self.ahead, "behind": self.behind}


@dataclass(frozen=True, slots=True)
class ReadObservation:
    observation: core.Observation
    reference_revision: str
    tracking: Tracking

    def as_dict(self) -> dict[str, Any]:
        return {"observation": self.observation.as_dict(), "referenceRevision": self.reference_revision,
                "tracking": self.tracking.as_dict(), "basis": "local-refs-no-fetch"}


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    oid: str
    parents: tuple[str, ...]
    committed_at: int

    def as_dict(self) -> dict[str, Any]:
        return {"oid": self.oid, "parents": list(self.parents), "committedAt": self.committed_at}


@dataclass(frozen=True, slots=True)
class History:
    revision: str
    reference_revision: str
    head: str | None
    commits: tuple[HistoryEntry, ...]
    has_more: bool
    shallow: bool

    def as_dict(self) -> dict[str, Any]:
        return {"revision": self.revision, "referenceRevision": self.reference_revision,
                "head": self.head, "commits": [row.as_dict() for row in self.commits],
                "hasMore": self.has_more, "shallow": self.shallow,
                "withheld": ["message", "author", "email", "signature"], "basis": "local-refs-no-fetch"}


class _ReadSession(core._Session):
    def __init__(self, repository: GitReadRepository):
        super().__init__(repository)
        self.deadline = min(self.deadline, repository.work_end)
        self.originals: _ReferenceInventory | None = None
        self.config: dict[str, tuple[bytes, ...]] | None = None
        self.initial_config = False
        self.head_bytes = b""
        self.scans: list[_Scan] = []

    def checkpoint(self) -> None:
        core._need(time.monotonic() < self.deadline, "deadline")
        if self.repository.cancellation is not None:
            self.repository.cancellation.check()

    def discover(self) -> None:
        self.checkpoint()
        self.git_dir = self.common_dir = self.root / ".git"
        core._need(stat.S_ISDIR(self.root.lstat().st_mode) and stat.S_ISDIR(self.git_dir.lstat().st_mode), "not-repository")
        self.originals = _inventory(self.git_dir, self.checkpoint, self.names)
        self.head_bytes = self.originals.body("HEAD")
        # Root the original scratch owner BEFORE initialization effects. A lost
        # constructor return cannot become an ordinary retryable refusal.
        self.frozen = core._FrozenGitDirectory.__new__(core._FrozenGitDirectory)
        core._FrozenGitDirectory.__init__(self.frozen)
        self.frozen.write("config", b"[core]\nbare = false\nrepositoryformatversion = 0\n")
        self.frozen.write("HEAD", b"ref: refs/heads/mrk-read-initial\n")
        self.frozen.write(_CONFIG_FILE, self.originals.body("config"))
        self.initial_config = True
        _, raw = self.git(["config", "--file", str(self.frozen.root / _CONFIG_FILE), "--no-includes", "--null", "--list"], limit=65536)
        self.initial_config = False
        self.config = _configuration(raw)
        # No original repository/config is used to determine the version.
        _, version = self.git(["--version"], limit=1024)
        matched = _VERSION.fullmatch(version)
        core._need(matched is not None and 43 <= int(matched[1]) <= 999, "unsupported-repository")
        self.freeze_configuration(self.config, None)
        for name, _ in self.originals.directories:
            if not name.startswith("refs/"):
                continue
            path = self.frozen.root / name
            path.mkdir(mode=0o700)
            self.frozen.directories[path] = core._identity(path.lstat())[:2]
        for name, stamp, body in self.originals.files:
            if name in ("HEAD", "packed-refs", "shallow") or name.startswith("refs/"):
                if stamp.kind == "file":
                    self.frozen.write(name, body)
        _, split = self.git(["rev-parse", "--shared-index-path"], limit=8192)
        core._need(not split.strip(), "unsupported-repository")
        self.check_original()

    def configuration(self) -> dict[str, tuple[bytes, ...]]:
        core._need(self.config is not None, "unsupported-repository")
        return dict(self.config)

    def names(self, path: Path) -> tuple[str, ...]:
        self.checkpoint()
        # At most one scan can be active. A lost open/close remains on THIS
        # original session; no implicit iterator finalizer or numeric retry.
        core._need(not self.scans, "unknown")
        original = _Scan()
        self.scans.append(original)
        try:
            original.entered = True
            try:
                original.iterator = os.scandir(path)
            except OSError:
                original.closed = True  # A returned failed open owns no iterator.
                raise
            result = []
            for entry in original.iterator:
                self.checkpoint()
                core._need(len(result) < MAX_LOOSE_REFS + MAX_REF_DIRECTORIES, "limit")
                result.append(_decoded(os.fsencode(entry.name), 255))
            return tuple(sorted(result))
        finally:
            original.close_claimed = True
            if original.iterator is not None:
                try:
                    original.iterator.close()
                    original.closed = True
                except BaseException:
                    self.repository._unknown = True
                    raise
            elif not original.closed:
                self.repository._unknown = True
            if original.closed:
                self.scans.remove(original)

    def freeze_configuration(self, config, head) -> None:
        super().freeze_configuration(config, head)
        assert self.frozen is not None
        _, base = core._read(self.frozen.root / "config", 65536)
        settings = (base + b"[core]\nattributesFile = /dev/null\nexcludesFile = /dev/null\n"
                    + _tracking_configuration(config))
        core._need(len(settings) <= 65536, "limit")
        self.frozen.write("config", settings)
        # The original helper uses a detached private HEAD for status. This
        # facet queries refs there too, so restore the exact copied HEAD bytes.
        self.frozen.write("HEAD", self.head_bytes)

    def check_original(self) -> None:
        assert self.git_dir is not None and self.originals is not None
        current = _inventory(self.git_dir, self.checkpoint, self.names)
        core._need(current == self.originals, "stale-observation")

    def snapshot(self) -> core._Snapshot:
        self.check_original()
        result = super().snapshot()
        core._need(not any(entry.mode == "160000" for rows in result.entries.values() for entry in rows),
                   "unsupported-repository")
        self.check_original()
        return result

    def reference_revision(self, observation: core.Observation) -> str:
        assert self.originals is not None
        return hashlib.sha256(b"mrk-git-read-refs/1\0" + observation.revision.encode("ascii")
                              + self.originals.comparison()).hexdigest()

    def command_spec(self, args: list[str]) -> tuple[list[str], dict[str, str]]:
        # Internal shared comparison for the actual fixed worker's run_owned
        # gate. A caller cannot supply the session or its scratch through IPC.
        core._need(self.frozen is not None and self.git_dir is not None
                   and _read_arguments(args, self.frozen.root / _CONFIG_FILE), "invalid-input")
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
            "HOME": str(self.frozen.root), "XDG_CONFIG_HOME": str(self.frozen.root),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "", "GIT_LITERAL_PATHSPECS": "1",
            "GIT_ATTR_NOSYSTEM": "1", "GIT_PAGER": "cat"}
        if not self.initial_config and args[0] != "--version":
            environment.update(GIT_OBJECT_DIRECTORY=str(self.git_dir / "objects"), GIT_INDEX_FILE=str(self.git_dir / "index"))
        argv = [str(self.repository.git_executable), "--no-pager", "--no-replace-objects",
                "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
                "-c", "core.untrackedCache=false", "-c", "protocol.allow=never",
                "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false",
                "-c", "maintenance.auto=false", "-c", "gc.auto=0",
                "--git-dir=" + str(self.frozen.root), "--work-tree=" + str(self.root), *args]
        return argv, environment

    def git(self, args: list[str], *, index=None, accept=(0,), limit=core.MAX_GIT_BYTES, identity=None):
        # No generic command descriptors or original-config discovery fallback.
        # All other core command methods are unreachable through this facet.
        self.checkpoint()
        core._need(index is None and identity is None and self.frozen is not None and self.git_dir is not None,
                   "invalid-input")
        core._need(_read_arguments(args, self.frozen.root / _CONFIG_FILE), "invalid-input")
        if self.initial_config:
            core._need(args == ["config", "--file", str(self.frozen.root / _CONFIG_FILE), "--no-includes", "--null", "--list"], "invalid-input")
        else:
            core._need(args[0] != "config" and self.config is not None, "invalid-input")
        self.calls += 1
        remaining = self.deadline - time.monotonic()
        core._need(self.calls <= core.MAX_CALLS, "limit")
        core._need(remaining >= 1, "deadline")
        argv, environment = self.command_spec(args)
        result = self.repository._run(argv, cwd=self.frozen.root, environ=environment, capture=True, text=False,
            timeout=min(10, math.floor(remaining)), output_limit=limit,
            cancellation=self.repository.cancellation, execution_scope=None)
        core._need(result.args == argv and type(result.returncode) is int and type(result.stdout) is bytes
                   and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= limit, "response-invalid")
        core._need(result.returncode in accept, "command-failed")
        if args[0] == "status":
            # Bound per-path ancestor work BEFORE the existing snapshot loops.
            for row in core._nul(result.stdout):
                core._need(len(row) >= 4 and len(row[3:].split(b"/")) <= MAX_REF_DEPTH, "limit")
        return result.returncode, result.stdout

    def tracking(self, observation: core.Observation) -> Tracking:
        if observation.branch is None:
            return Tracking("detached")
        assert self.config is not None and self.originals is not None
        prefix = "branch." + observation.branch[len("refs/heads/"):] + "."
        remote, merge = self.config.get(prefix + "remote", ()), self.config.get(prefix + "merge", ())
        if not remote and not merge:
            return Tracking("unborn" if observation.head is None else "not-configured")
        if len(remote) != 1 or len(merge) != 1:
            return Tracking("unsupported")
        remote_name, merge_ref = _decoded(remote[0], 128), _decoded(merge[0])
        if not remote_name or not _full_ref(merge_ref):
            return Tracking("unsupported")
        if observation.head is None:
            return Tracking("unborn", remote_name, merge_ref)
        _, body = self.git(["for-each-ref", "--count=1", "--sort=refname", "--format=" + _FORMAT,
                            "--", observation.branch], limit=4096)
        core._need(body.endswith(b"\0\n") and body.count(b"\n") == 1, "response-invalid")
        fields = body[:-1].split(b"\0")
        core._need(len(fields) == 5 and fields[-1] == b"" and _decoded(fields[0]) == observation.branch,
                   "response-invalid")
        upstream, selected_remote, selected_merge = (_decoded(value) if value else "" for value in fields[1:4])
        if not upstream:
            return Tracking("unsupported", remote_name, merge_ref)
        core._need(_full_ref(upstream) and selected_remote == remote_name and selected_merge == merge_ref,
                   "response-invalid")
        code, body = self.git(["rev-parse", "--verify", "--quiet", "--end-of-options", upstream + "^{commit}"],
                              accept=(0, 1), limit=128)
        if code == 1:
            return Tracking("gone", remote_name, merge_ref, upstream)
        oid = core._oid(body)
        core._need(len(oid) == len(observation.head))
        if self.originals.shallow:
            return Tracking("shallow", remote_name, merge_ref, upstream, oid)
        _, body = self.git(["rev-list", "--left-right", "--count", "--max-count=" + str(MAX_WALK + 1),
                            observation.head + "..." + oid, "--"], limit=64)
        match = re.fullmatch(rb"([0-9]{1,5})\t([0-9]{1,5})\n", body)
        core._need(match is not None)
        ahead, behind = int(match[1]), int(match[2])
        if ahead + behind > MAX_WALK:
            return Tracking("limit", remote_name, merge_ref, upstream, oid)
        return Tracking("complete", remote_name, merge_ref, upstream, oid, ahead, behind)


class GitReadRepository(core.GitRepository):
    """Library facade used only by the fixed native GitRead operation.

    ``work_end`` is the original admitted absolute deadline, never a renewed
    per-request allowance. Constructor data alone supplies no native authority.
    """
    def __init__(self, root: Path, *, git_executable: Path, work_end: float, cancellation=None,
                 _run=core.run_owned):
        core._need(type(work_end) in (float, int) and math.isfinite(work_end), "invalid-input")
        super().__init__(root, git_executable=git_executable, cancellation=cancellation, _run=_run)
        self.work_end = work_end

    def _session(self) -> _ReadSession:
        core._need(not self._unknown, "unknown")
        session = _ReadSession(self)
        self._active_sessions.append(session)
        session.discover()
        return session

    @core._session_boundary
    def observe(self) -> ReadObservation:
        session = self._session()
        before = session.snapshot()
        tracking = session.tracking(before.public)
        self._expected(session.snapshot(), before.public.revision)
        return ReadObservation(before.public, session.reference_revision(before.public), tracking)

    @core._session_boundary
    def history(self, *, expected_revision: str) -> History:
        session = self._session()
        before = session.snapshot()
        self._expected(before, expected_revision)
        head = before.public.head
        rows = []
        if head is not None:
            _, body = session.git(["rev-list", "--timestamp", "--parents", "--max-count=" + str(HISTORY_COUNT + 1),
                                   head, "--"], limit=MAX_HISTORY_BYTES)
            core._need(body.endswith(b"\n"))
            seen = set()
            for line in body.splitlines():
                fields = line.split(b" ")
                core._need(2 <= len(fields) <= 66 and re.fullmatch(rb"[0-9]{1,12}", fields[0]) is not None)
                oid, *parents = (core._oid(value) for value in fields[1:])
                core._need(oid not in seen and all(len(value) == len(head) for value in (oid, *parents))
                           and len(set(parents)) == len(parents) and oid not in parents)
                seen.add(oid)
                rows.append(HistoryEntry(oid, tuple(parents), int(fields[0])))
                core._need(len(rows) <= HISTORY_COUNT + 1, "limit")
            core._need(rows and rows[0].oid == head)
        self._expected(session.snapshot(), expected_revision)
        assert session.originals is not None
        return History(expected_revision, session.reference_revision(before.public), head,
                       tuple(rows[:HISTORY_COUNT]), len(rows) > HISTORY_COUNT, session.originals.shallow)

    def _refuse_write(self, *args, **kwargs):
        raise core.GitError("invalid-input")

    prepare_stage = prepare_unstage = prepare_commit = apply = reconcile = _refuse_write
