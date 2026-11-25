"""Bounded local Git operations, not a shell or a release authorization source.

The caller supplies a registered root and retains its shared project invocation.
Mutations additionally require an in-process owner which revalidates authorization
and durably records the exact publication intent. No such owner comes from JSON.
Git's own index/ref locks and expected-old ref updates coordinate external Git.
Checks detect persistent external edits; they are not protection against hostile
same-user namespace changes/ABA or an atomic snapshot of an entire checkout.

This first slice supports full, nonsparse repositories (including linked
worktrees), selected regular files, and attached/unborn commits of the WHOLE
reviewed index. Required hooks, filters and commit signing are not bypassed.
There is deliberately no reset, checkout, fetch, push, shell or option endpoint.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import wraps
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from typing import Any, Callable, Protocol

from .errors import ValidationError
from .owned_process import ProcessError, fatal_lifetime_error, run_owned

MAX_INDEX_BYTES = 16 * 1024 * 1024
MAX_GIT_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_DIFF_BYTES = 256 * 1024
MAX_ENTRIES = 32768
MAX_CHANGES = 512
MAX_SELECTED = 64
MAX_CALLS = 256
WORK_SECONDS = 45
_ERROR = "The Git operation could not safely complete."
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_REVISION = re.compile(r"[0-9a-f]{64}\Z")
_ACTIVE_HOOKS = frozenset(("pre-commit", "prepare-commit-msg", "commit-msg", "post-commit",
    "post-rewrite", "reference-transaction", "post-index-change", "pre-auto-gc"))
_OPERATION_MARKERS = ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "REBASE_HEAD",
                      "rebase-merge", "rebase-apply", "sequencer")
_SECRET = re.compile(rb"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY)-----|"
    rb"\bgh[pousr]_[A-Za-z0-9_]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b|"
    rb'"type"\s*:\s*"service_account"')
_REASONS = frozenset(("invalid-input", "not-repository", "unsupported-repository", "unsupported-path",
    "unsupported-filter", "required-hooks", "required-signing", "conflicts", "nothing-staged",
    "sensitive-content", "stale-observation", "locked", "authorization", "deadline", "limit",
    "command-failed", "response-invalid", "recovery-required", "unknown", "already-used",
    "operation-in-progress"))


class GitError(ValidationError):
    def __init__(self, reason: str):
        if reason not in _REASONS:
            reason = "response-invalid"
        self.reason = reason
        super().__init__(_ERROR)


def _need(condition: bool, reason: str = "response-invalid") -> None:
    if not condition:
        raise GitError(reason)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _text(value: Any, limit: int = 1024) -> str:
    _need(type(value) is str and 0 < len(value.encode("utf-8")) <= limit
          and not any(ord(c) < 32 or ord(c) == 127 for c in value), "invalid-input")
    return value


def _path(value: Any) -> str:
    value = _text(value)
    _need("\\" not in value and not value.startswith("/")
          and all(part not in ("", ".", "..", ".git") and len(part.encode("utf-8")) <= 255
                  for part in value.split("/")), "unsupported-path")
    return value


def _paths(values: Any) -> tuple[str, ...]:
    _need(type(values) in (list, tuple) and 1 <= len(values) <= MAX_SELECTED, "invalid-input")
    result = tuple(_path(value) for value in values)
    _need(len(set(result)) == len(result), "invalid-input")
    return tuple(sorted(result))


def _oid(value: bytes) -> str:
    try:
        result = value.decode("ascii").removesuffix("\n")
    except UnicodeError:
        raise GitError("response-invalid") from None
    _need(_OID.fullmatch(result) is not None)
    return result


def _ref(value: str) -> bool:
    return (value.startswith("refs/heads/") and len(value.encode("utf-8")) <= 1024
            and not any(ord(c) < 33 or ord(c) == 127 or c in "~^:?*[\\" for c in value)
            and ".." not in value and "@{" not in value and "//" not in value
            and all(part and not part.startswith(".") and not part.endswith((".", ".lock"))
                    for part in value.split("/")))


def _sensitive_path(path: str) -> bool:
    parts = path.lower().split("/")
    leaf = parts[-1]
    return (leaf == ".env" or leaf.startswith(".env.") or leaf in
            ("id_rsa", "id_ed25519", "credentials.json", "service-account.json", "hosts.yml")
            or leaf.endswith((".p8", ".p12", ".pfx", ".pem", ".key", ".jks", ".keystore"))
            or any(part.startswith((".mobile-release-init", ".mrk-private")) for part in parts))


@dataclass(frozen=True, slots=True)
class CommitIdentity:
    name: str
    email: str

    def validate(self) -> None:
        _text(self.name, 128)
        _text(self.email, 254)
        _need(not any(c in "<>" for c in self.name) and re.fullmatch(r"[^\s<>@]+@[^\s<>@]+", self.email)
              is not None, "invalid-input")


@dataclass(frozen=True, slots=True)
class Change:
    path: str
    index: str
    worktree: str
    kind: str
    conflict: bool

    def as_dict(self) -> dict[str, Any]:
        return {"path": self.path, "index": self.index, "worktree": self.worktree,
                "kind": self.kind, "conflict": self.conflict}


@dataclass(frozen=True, slots=True)
class Observation:
    revision: str
    head: str | None
    branch: str | None
    changes: tuple[Change, ...]
    remotes: tuple[str, ...]
    restrictions: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        # Remote URLs/configuration, absolute paths and raw command output are
        # intentionally absent. A URL can contain a credential.
        return {"revision": self.revision, "head": self.head, "branch": self.branch,
                "unborn": self.head is None, "detached": self.branch is None,
                "changes": [row.as_dict() for row in self.changes],
                "remotes": list(self.remotes), "restrictions": list(self.restrictions)}


@dataclass(frozen=True, slots=True)
class Diff:
    revision: str
    staged: bool
    paths: tuple[str, ...]
    text: str | None
    withheld: str | None

    def as_dict(self) -> dict[str, Any]:
        return {"revision": self.revision, "staged": self.staged, "paths": list(self.paths),
                "text": self.text, "withheld": self.withheld}


@dataclass(frozen=True, slots=True)
class PublicationIntent:
    action: str
    expected_revision: str
    expected_ref: str | None
    expected_head: str | None
    expected_index: str
    candidate_index: str | None
    candidate_commit: str | None

    def as_dict(self) -> dict[str, Any]:
        return {"action": self.action, "expectedRevision": self.expected_revision,
                "expectedRef": self.expected_ref, "expectedHead": self.expected_head,
                "expectedIndex": self.expected_index, "candidateIndex": self.candidate_index,
                "candidateCommit": self.candidate_commit}


class MutationOwner(Protocol):
    """Root's original shared invocation, not a serializable authorization flag.

    check_current must validate project/root, client/session, action, revision,
    cancellation and original lease. record_intent MUST durably retain the
    pending operation and its exact intent before returning permission to send.
    The owner remains alive until run_owned and this method actually settle.
    """
    operation_id: str

    def check_current(self, root: Path, action: str, expected_revision: str) -> None: ...

    def record_intent(self, intent: PublicationIntent) -> None: ...


@dataclass(frozen=True, slots=True)
class MutationResult:
    operation_id: str
    action: str
    state: str
    settlement: str
    reason: str | None
    observation: Observation | None
    intent: PublicationIntent | None

    def as_dict(self) -> dict[str, Any]:
        return {"operationId": self.operation_id, "action": self.action, "state": self.state,
                "settlement": self.settlement, "reason": self.reason,
                "observation": None if self.observation is None else self.observation.as_dict(),
                "intent": None if self.intent is None else self.intent.as_dict()}


@dataclass(frozen=True, slots=True, repr=False)
class _Stamp:
    kind: str
    identity: tuple[int, ...]
    digest: str


_ABSENT = _Stamp("absent", (), _digest(b"absent"))


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read(path: Path, limit: int, *, regular: bool = True) -> tuple[_Stamp, bytes]:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return _ABSENT, b""
    if not stat.S_ISREG(before.st_mode):
        _need(not regular, "unsupported-path")
        kind = "directory" if stat.S_ISDIR(before.st_mode) else "symlink" if stat.S_ISLNK(before.st_mode) else "other"
        return _Stamp(kind, _identity(before), ""), b""
    _need(before.st_size <= limit, "limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        _need(_identity(os.fstat(fd)) == _identity(before), "stale-observation")
        chunks: list[bytes] = []
        count = 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            _need(count <= limit, "limit")
        _need(_identity(os.fstat(fd)) == _identity(before)
              and _identity(path.lstat()) == _identity(before), "stale-observation")
        content = b"".join(chunks)
        return _Stamp("file", _identity(before), _digest(content)), content
    finally:
        os.close(fd)


def _nul(value: bytes) -> list[bytes]:
    _need(not value or value.endswith(b"\0"))
    return value[:-1].split(b"\0") if value else []


def _decode_path(value: bytes) -> str:
    try:
        return _path(value.decode("utf-8", "strict"))
    except UnicodeError:
        raise GitError("unsupported-path") from None


@dataclass(frozen=True, slots=True)
class _Entry:
    mode: str
    oid: str
    stage: int


def _entries(value: bytes) -> dict[str, tuple[_Entry, ...]]:
    result: dict[str, tuple[_Entry, ...]] = {}
    for row in _nul(value):
        head, separator, name = row.partition(b"\t")
        fields = head.split(b" ")
        _need(separator == b"\t" and len(fields) == 3 and fields[0] in
              (b"100644", b"100755", b"120000", b"160000") and fields[2] in (b"0", b"1", b"2", b"3"))
        path = _decode_path(name)
        entry = _Entry(fields[0].decode("ascii"), _oid(fields[1]), int(fields[2]))
        previous = result.get(path, ())
        _need(not previous or previous[-1].stage < entry.stage)
        result[path] = (*previous, entry)
        _need(len(result) <= MAX_ENTRIES, "limit")
    return result


@dataclass(slots=True, repr=False)
class _Snapshot:
    public: Observation
    entries: dict[str, tuple[_Entry, ...]]
    index_stamp: _Stamp
    index_bytes: bytes
    file_stamps: dict[str, _Stamp]
    metadata: dict[Path, _Stamp]
    config: dict[str, tuple[bytes, ...]]
    operations: dict[str, _Stamp]


@dataclass(slots=True, repr=False)
class GitPlan:
    """Private, original prepare result. Wire assertions cannot reconstruct it."""
    action: str
    paths: tuple[str, ...]
    _key: object = field(repr=False)
    _snapshot: _Snapshot = field(repr=False)
    _selected: dict[str, _Stamp] = field(repr=False)
    _message: str | None = field(default=None, repr=False)
    _identity: CommitIdentity | None = field(default=None, repr=False)
    _used: bool = field(default=False, repr=False)

    def as_dict(self) -> dict[str, Any]:
        return {"action": self.action, "expectedRevision": self._snapshot.public.revision,
                "paths": list(self.paths), "wholeIndex": self.action == "commit",
                "head": self._snapshot.public.head, "branch": self._snapshot.public.branch}


class _FrozenGitDirectory:
    """Minimal private configuration, never the application's mutable config.

    Only fixed non-executable Git settings are copied. Commands that can invoke
    clean/process filters cannot observe a newly added original filter command,
    even if an external writer changes config after our policy census. Original
    policy/attributes are still checked for drift before source publication.
    """
    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="mrk-git-read-"))
        os.chmod(self.root, 0o700)
        self.directories = {self.root: _identity(self.root.lstat())[:2]}
        self.files: dict[Path, _Stamp] = {}
        self.unknown = False
        for leaf in ("objects", "refs", "info"):
            path = self.root / leaf
            path.mkdir(mode=0o700)
            self.directories[path] = _identity(path.lstat())[:2]

    def write(self, name: str, content: bytes) -> None:
        path = self.root / name
        previous = self.files.get(path)
        _need(previous is None and not path.exists() or previous is not None and _read(path, 65536)[0] == previous,
              "recovery-required")
        flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= os.O_CREAT | os.O_EXCL if previous is None else os.O_TRUNC
        fd = os.open(path, flags, 0o600)
        try:
            offset = 0
            while offset < len(content):
                count = os.write(fd, content[offset:])
                _need(count > 0, "recovery-required")
                offset += count
        finally:
            # This local route has only one close call. Any exception prevents
            # inventory adoption and the enclosing session retains this owner.
            os.close(fd)
        self.files[path] = _read(path, 65536)[0]

    def close(self) -> bool:
        try:
            for path, identity in self.directories.items():
                _need(_identity(path.lstat())[:2] == identity and stat.S_ISDIR(path.lstat().st_mode),
                      "recovery-required")
                expected = {entry for entry in (*self.directories, *self.files) if entry != path and entry.parent == path}
                _need(set(path.iterdir()) == expected, "recovery-required")
            _need(all(_read(path, 65536)[0] == stamp for path, stamp in self.files.items()), "recovery-required")
            for path in tuple(self.files):
                del self.files[path]  # Retire before the one unlink attempt.
                os.unlink(path)
            for path in sorted(self.directories, key=lambda path: len(path.parts), reverse=True):
                del self.directories[path]
                os.rmdir(path)
            return True
        except (GitError, OSError):
            self.unknown = True
            return False
        except BaseException:
            self.unknown = True
            raise


def _session_boundary(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        _need(not self._active_sessions, "locked")
        try:
            result = method(self, *args, **kwargs)
        except BaseException as error:
            fatal = fatal_lifetime_error(error, _ERROR)
            uncertain = self._unknown or fatal is not None or not isinstance(error, (GitError, ProcessError, OSError))
            self._finish_sessions(uncertain)
            raise
        uncertain = self._unknown or isinstance(result, MutationResult) and result.settlement == "unknown"
        if not self._finish_sessions(uncertain):
            if isinstance(result, MutationResult):
                return MutationResult(result.operation_id, result.action, "unknown", "unknown", "unknown", None, result.intent)
            raise GitError("unknown")
        return result
    return call


class _Session:
    def __init__(self, repository: GitRepository):
        self.repository = repository
        self.root = repository.root
        self.git_dir: Path | None = None
        self.common_dir: Path | None = None
        self.deadline = time.monotonic() + WORK_SECONDS
        self.calls = 0
        self.frozen: _FrozenGitDirectory | None = None

    def git(self, args: list[str], *, index: Path | None = None, accept: tuple[int, ...] = (0,),
            limit: int = MAX_GIT_BYTES, identity: CommitIdentity | None = None) -> tuple[int, bytes]:
        self.calls += 1
        remaining = self.deadline - time.monotonic()
        _need(self.calls <= MAX_CALLS, "limit")
        _need(remaining >= 1, "deadline")
        environment = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "", "GIT_LITERAL_PATHSPECS": "1",
            "GIT_ATTR_NOSYSTEM": "1", "GIT_PAGER": "cat"}
        filter_capable = args[0] in {"status", "diff", "add", "restore", "check-attr", "ls-files",
                                    "write-tree", "commit-tree", "cat-file", "update-index"}
        if filter_capable:
            _need(self.frozen is not None and self.git_dir is not None and self.common_dir is not None,
                  "unsupported-repository")
            environment["GIT_OBJECT_DIRECTORY"] = str(self.common_dir / "objects")
            environment["GIT_INDEX_FILE"] = str(index if index is not None else self.git_dir / "index")
        elif index is not None:
            raise GitError("invalid-input")
        if identity is not None:
            identity.validate()
            environment.update({"GIT_AUTHOR_NAME": identity.name, "GIT_AUTHOR_EMAIL": identity.email,
                "GIT_COMMITTER_NAME": identity.name, "GIT_COMMITTER_EMAIL": identity.email})
        argv = [str(self.repository.git_executable), "--no-pager", "--no-replace-objects",
                "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
                "-c", "core.untrackedCache=false", "-c", "protocol.allow=never",
                "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false",
                "-c", "maintenance.auto=false", "-c", "gc.auto=0"]
        if self.git_dir is not None:
            directory = self.frozen.root if filter_capable and self.frozen is not None else self.git_dir
            argv += ["--git-dir=" + str(directory), "--work-tree=" + str(self.root)]
        argv += args
        result = self.repository._run(argv, cwd=self.root, environ=environment, capture=True, text=False,
            timeout=min(10, math.floor(remaining)), output_limit=limit,
            cancellation=self.repository.cancellation,
            execution_scope=None if self.repository.execution_source is None else self.repository.execution_source.new_scope())
        _need(result.args == argv and type(result.returncode) is int and type(result.stdout) is bytes
              and type(result.stderr) is bytes and len(result.stdout) <= limit, "response-invalid")
        _need(result.returncode in accept, "command-failed")
        return result.returncode, result.stdout

    def _git_path(self, option: str) -> Path:
        _, value = self.git(["rev-parse", option], limit=8192)
        try:
            name = value.decode("utf-8").removesuffix("\n")
            _text(name, 4096)
            path = Path(name)
            return (path if path.is_absolute() else self.root / path).resolve(strict=True)
        except (OSError, UnicodeError, ValueError):
            raise GitError("not-repository") from None

    def discover(self) -> None:
        _need(self.root.is_dir(), "not-repository")
        # These commands read configuration but cannot run filters, hooks or
        # external diff. Config includes are refused before status/diff/add.
        top = self._git_path("--show-toplevel")
        _need(top == self.root, "not-repository")
        self.git_dir = self._git_path("--absolute-git-dir")
        self.common_dir = self._git_path("--git-common-dir")
        _, split = self.git(["rev-parse", "--shared-index-path"], limit=8192)
        _need(not split.strip(), "unsupported-repository")
        for path in (self.git_dir, self.common_dir):
            _need(stat.S_ISDIR(path.lstat().st_mode), "unsupported-repository")
        _need(not (self.common_dir / "objects/info/alternates").exists(), "unsupported-repository")

    def metadata_paths(self) -> tuple[Path, ...]:
        assert self.git_dir is not None and self.common_dir is not None
        paths = [self.common_dir / "config", self.git_dir / "config.worktree", self.git_dir / "HEAD",
                 self.git_dir / "commondir", self.common_dir / "info/attributes", self.common_dir / "info/exclude",
                 self.root / ".gitattributes"]
        if (self.root / ".git").is_file():
            paths.append(self.root / ".git")
        return tuple(dict.fromkeys(paths))

    def configuration(self) -> dict[str, tuple[bytes, ...]]:
        config: dict[str, tuple[bytes, ...]] = {}
        sources = [["config", "--local", "--no-includes", "--null", "--list"]]
        for args in sources:
            _, body = self.git(args, limit=65536)
            for row in _nul(body):
                key, separator, value = row.partition(b"\n")
                _need(separator == b"\n" and 0 < len(key) <= 1024)
                try:
                    name = key.decode("ascii").lower()
                except UnicodeError:
                    raise GitError("unsupported-repository") from None
                _need(name != "include.path" and not name.startswith("includeif."), "unsupported-repository")
                _need(not name.startswith("filter."), "unsupported-filter")
                _need(name not in ("core.attributesfile", "core.excludesfile", "core.checkroundtripencoding"),
                      "unsupported-repository")
                config[name] = (*config.get(name, ()), value)
            # Other Git truthy spellings and duplicates must not cause later
            # Git commands to load a worktree config omitted from this census.
            _need(config.get("extensions.worktreeconfig", (b"false",)) in ((b"true",), (b"false",)),
                  "unsupported-repository")
            if len(sources) == 1 and config.get("extensions.worktreeconfig") == (b"true",):
                sources.append(["config", "--worktree", "--no-includes", "--null", "--list"])
        _need(config.get("core.bare", (b"false",)) == (b"false",), "unsupported-repository")
        return config

    def freeze_configuration(self, config: dict[str, tuple[bytes, ...]], head: str | None) -> None:
        assert self.common_dir is not None
        if self.frozen is None:
            self.frozen = _FrozenGitDirectory()
        object_format = config.get("extensions.objectformat", (b"sha1",))
        _need(object_format in ((b"sha1",), (b"sha256",)), "unsupported-repository")
        lines = [b"[core]", b"bare = false", b"repositoryformatversion = " + (b"1" if object_format == (b"sha256",) else b"0")]
        for name in ("filemode", "ignorecase", "precomposeunicode", "symlinks"):
            if "core." + name in config:
                raw = config["core." + name][-1].lower()
                _need(raw in (b"", b"1", b"true", b"yes", b"on", b"0", b"false", b"no", b"off"),
                      "unsupported-repository")
                value = b"true" if raw in (b"", b"1", b"true", b"yes", b"on") else b"false"
                lines.append(name.encode("ascii") + b" = " + value)
        for name, choices in (("autocrlf", (b"true", b"false", b"input")), ("eol", (b"lf", b"crlf", b"native")),
                              ("safecrlf", (b"true", b"false", b"warn"))):
            if "core." + name in config:
                value = config["core." + name][-1].lower()
                _need(value in choices, "unsupported-repository")
                lines.append(name.encode("ascii") + b" = " + value)
        if object_format == (b"sha256",):
            lines += [b"[extensions]", b"objectFormat = sha256"]
        self.frozen.write("config", b"\n".join(lines) + b"\n")
        self.frozen.write("HEAD", (head.encode("ascii") if head is not None else b"ref: refs/heads/mrk-unborn") + b"\n")
        for name in ("attributes", "exclude"):
            self.frozen.write("info/" + name, _read(self.common_dir / "info" / name, 65536)[1])

    def head(self) -> tuple[str | None, str | None]:
        code, body = self.git(["symbolic-ref", "--quiet", "HEAD"], accept=(0, 1), limit=2048)
        branch = None
        if code == 0:
            try:
                branch = body.decode("utf-8").removesuffix("\n")
            except UnicodeError:
                raise GitError("response-invalid") from None
            _need(_ref(branch), "unsupported-repository")
            alias, _ = self.git(["symbolic-ref", "--quiet", branch], accept=(0, 1), limit=2048)
            _need(alias == 1, "unsupported-repository")
        code, body = self.git(["rev-parse", "--verify", "--quiet", "HEAD^{commit}"], accept=(0, 1), limit=128)
        if code == 0:
            return _oid(body), branch
        _need(branch is not None, "not-repository")
        absent, _ = self.git(["show-ref", "--verify", "--quiet", branch], accept=(0, 1), limit=1024)
        _need(absent == 1, "not-repository")
        return None, branch

    def selected_stamp(self, path: str) -> tuple[_Stamp, bytes]:
        current = self.root
        for part in path.split("/")[:-1]:
            current /= part
            try:
                info = current.lstat()
            except FileNotFoundError:
                return _ABSENT, b""
            _need(stat.S_ISDIR(info.st_mode) and not (current / ".git").exists(), "unsupported-path")
        return _read(self.root / path, MAX_FILE_BYTES, regular=False)

    def restrictions(self, config: dict[str, tuple[bytes, ...]]) -> tuple[str, ...]:
        assert self.common_dir is not None
        reasons = set()
        if "core.hookspath" in config:
            reasons.add("required-hooks")
        hooks = self.common_dir / "hooks"
        if hooks.exists():
            _need(stat.S_ISDIR(hooks.lstat().st_mode), "unsupported-repository")
            for name in _ACTIVE_HOOKS:
                try:
                    info = (hooks / name).lstat()
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o111:
                    reasons.add("required-hooks")
        if config.get("commit.gpgsign", (b"false",)) != (b"false",):
            reasons.add("required-signing")
        if any(config.get(name, (b"false",)) != (b"false",)
               for name in ("core.sparsecheckout", "index.sparse", "core.splitindex")):
            reasons.add("unsupported-repository")
        return tuple(sorted(reasons))

    def operation_markers(self) -> dict[str, _Stamp]:
        assert self.git_dir is not None
        # Fixed per-worktree names only; do not traverse, repair or remove Git's
        # in-progress state. Absence is part of the reviewed expected state.
        return {name: _read(self.git_dir / name, 65536, regular=False)[0] for name in _OPERATION_MARKERS}

    def snapshot(self) -> _Snapshot:
        assert self.git_dir is not None
        operations = self.operation_markers()
        metadata = {path: _read(path, 65536)[0] for path in self.metadata_paths()}
        config = self.configuration()
        head, branch = self.head()
        self.freeze_configuration(config, head)
        index_stamp, index_bytes = _read(self.git_dir / "index", MAX_INDEX_BYTES)
        _, raw_index = self.git(["ls-files", "--stage", "-z"])
        entries = _entries(raw_index)
        _, status_body = self.git(["status", "--porcelain=v1", "-z", "--untracked-files=all",
                                   "--ignore-submodules=all", "--no-renames"])
        changes: list[Change] = []
        stamps: dict[str, _Stamp] = {}
        source_bytes = 0
        for row in _nul(status_body):
            _need(len(row) >= 4 and row[2:3] == b" " and row[0] in b" MTADRCU?!" and row[1] in b" MTADRCU?!")
            path = _decode_path(row[3:].removesuffix(b"/"))
            _need(path not in stamps and len(changes) < MAX_CHANGES, "limit")
            stamp, _ = self.selected_stamp(path)
            stamps[path] = stamp
            source_bytes += stamp.identity[3] if stamp.kind == "file" else 0
            _need(source_bytes <= MAX_SOURCE_BYTES, "limit")
            for parent in (self.root / path).parents:
                if parent == self.root:
                    break
                attr = parent / ".gitattributes"
                metadata[attr] = _read(attr, 65536)[0]
            conflict = row[:2] in (b"DD", b"AU", b"UD", b"UA", b"DU", b"AA", b"UU")
            mode = entries.get(path, ())
            kind = "submodule" if any(entry.mode == "160000" for entry in mode) else stamp.kind
            changes.append(Change(path, chr(row[0]), chr(row[1]), kind, conflict))
        restrictions = self.restrictions(config)
        if any(stamp.kind != "absent" for stamp in operations.values()):
            restrictions = tuple(sorted((*restrictions, "operation-in-progress")))
        _need(self.head() == (head, branch) and _read(self.git_dir / "index", MAX_INDEX_BYTES)[0] == index_stamp,
              "stale-observation")
        _need(all(_read(path, 65536)[0] == stamp for path, stamp in metadata.items()), "stale-observation")
        _need(all(self.selected_stamp(path)[0] == stamp for path, stamp in stamps.items()), "stale-observation")
        _need(self.operation_markers() == operations, "stale-observation")
        remotes = []
        for key in config:
            if key.startswith("remote.") and key.endswith(".url"):
                name = key[7:-4]
                _text(name, 128)
                remotes.append(name)
        data = {"head": head, "branch": branch, "index": index_stamp.digest,
                "indexIdentity": index_stamp.identity, "root": _identity(self.root.stat())[:2],
                "git": _identity(self.git_dir.stat())[:2], "status": _digest(status_body),
                "files": [(name, value.kind, value.identity, value.digest) for name, value in sorted(stamps.items())],
                "metadata": [(str(name), value.identity, value.digest) for name, value in sorted(metadata.items())],
                "operations": [(name, value.kind, value.identity, value.digest) for name, value in operations.items()],
                "restrictions": restrictions}
        revision = _digest(json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        public = Observation(revision, head, branch, tuple(sorted(changes, key=lambda row: row.path)),
                             tuple(sorted(remotes)), restrictions)
        return _Snapshot(public, entries, index_stamp, index_bytes, stamps, metadata, config, operations)

    def validate_paths(self, paths: tuple[str, ...], snapshot: _Snapshot, *, staging: bool) -> dict[str, _Stamp]:
        stamps: dict[str, _Stamp] = {}
        for path in paths:
            entries = snapshot.entries.get(path, ())
            _need(all(entry.stage == 0 for entry in entries), "conflicts")
            _need(all(entry.mode in ("100644", "100755") for entry in entries), "unsupported-path")
            stamp, body = self.selected_stamp(path)
            removed = any(row.path == path and row.index == "D" for row in snapshot.public.changes)
            _need(stamp.kind in ("absent", "file") and (entries or stamp.kind == "file" or removed), "unsupported-path")
            if staging:
                _need(not _sensitive_path(path) and _SECRET.search(body) is None, "sensitive-content")
            stamps[path] = stamp
        _, attrs = self.git(["check-attr", "-z", "filter", "--", *paths], limit=65536)
        rows = _nul(attrs)
        _need(len(rows) == 3 * len(paths))
        for offset in range(0, len(rows), 3):
            _need(_decode_path(rows[offset]) == paths[offset // 3] and rows[offset + 1] == b"filter")
            _need(rows[offset + 2] in (b"unspecified", b"unset"), "unsupported-filter")
        return stamps


class _IndexTransaction:
    """Own only the exact locks/scratch created here; never delete foreign state."""
    def __init__(self, session: _Session, original: _Snapshot):
        assert session.git_dir is not None
        self.session = session
        self.original = original
        self.locks: list[tuple[Path, int, tuple[int, ...]]] = []
        self.scratch: Path | None = None
        self.scratch_files: dict[Path, tuple[int, ...]] = {}
        self.published = False
        self.retained = False
        self.index: Path | None = None
        self.uncertain_closes: list[tuple[Path, int, tuple[int, ...]]] = []

    def acquire(self) -> None:
        assert self.session.git_dir is not None
        for name in ("index.lock", "HEAD.lock"):
            path = self.session.git_dir / name
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_CLOEXEC", 0), 0o600)
            except FileExistsError:
                raise GitError("locked") from None
            self.locks.append((path, fd, _identity(os.fstat(fd))))
        self.check_original()
        self.scratch = Path(tempfile.mkdtemp(prefix="mrk-git-", dir=self.session.git_dir))
        os.chmod(self.scratch, 0o700)
        self.index = self.scratch / "index"
        if self.original.index_stamp.kind != "absent":
            self.index.write_bytes(self.original.index_bytes)
            os.chmod(self.index, 0o600)
            self.remember_candidate()

    def check_original(self) -> None:
        assert self.session.git_dir is not None
        _need(_read(self.session.git_dir / "index", MAX_INDEX_BYTES)[0] == self.original.index_stamp,
              "stale-observation")
        _need(self.session.head() == (self.original.public.head, self.original.public.branch), "stale-observation")
        _need(all(_read(path, 65536)[0] == stamp for path, stamp in self.original.metadata.items()),
              "stale-observation")
        _need(self.session.operation_markers() == self.original.operations, "stale-observation")
        for path, fd, identity in self.locks:
            current = path.lstat()
            _need(_identity(current)[:2] == identity[:2] == _identity(os.fstat(fd))[:2], "stale-observation")

    def remember_candidate(self) -> None:
        assert self.index is not None
        if self.index.exists():
            _need(stat.S_ISREG(self.index.lstat().st_mode), "recovery-required")
            self.scratch_files[self.index] = _identity(self.index.lstat())

    def release_head_lock(self) -> None:
        # update-ref must own its actual HEAD/ref locks. The approved branch
        # name remains pinned and expected-old is checked by Git itself; never
        # switch the target to mutable HEAD after dropping this preparation lock.
        _need(len(self.locks) == 2 and self.locks[-1][0].name == "HEAD.lock", "recovery-required")
        path, fd, identity = self.locks[-1]
        _need(_identity(path.lstat())[:2] == identity[:2] == _identity(os.fstat(fd))[:2], "stale-observation")
        os.unlink(path)
        self.locks.pop()  # Retire the close route before its one close attempt.
        self.uncertain_closes.append((path, fd, identity))
        os.close(fd)
        self.uncertain_closes.pop()

    def publish_index(self) -> None:
        assert self.index is not None and self.session.git_dir is not None
        candidate, content = _read(self.index, MAX_INDEX_BYTES)
        _need(candidate.kind == "file")
        self.check_original()
        lock, fd, _ = self.locks[0]
        offset = 0
        while offset < len(content):
            count = os.write(fd, content[offset:])
            _need(count > 0, "recovery-required")
            offset += count
        if self.original.index_stamp.kind == "file":
            os.fchmod(fd, stat.S_IMODE(self.original.index_stamp.identity[2]))
        os.fsync(fd)
        self.check_original()
        # Same-directory replacement is guarded by Git's index.lock. It is
        # NOT a compare-and-swap against a hostile writer ignoring that lock.
        os.replace(lock, self.session.git_dir / "index")
        self.published = True
        directory = os.open(self.session.git_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                            | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def close(self, *, preserve_scratch: bool = False) -> bool:
        good = True
        while self.locks:
            # Retire this exact original route BEFORE cleanup can raise. A
            # partial/ambiguous close is retained, never retried against a fd
            # number that the operating system may already have reused.
            path, fd, identity = self.locks.pop(0)
            try:
                if not (path.name == "index.lock" and self.published):
                    if _identity(path.lstat())[:2] != identity[:2]:
                        good = False
                    else:
                        os.unlink(path)
            except OSError:
                good = False
            finally:
                self.uncertain_closes.append((path, fd, identity))
                try:
                    os.close(fd)
                except OSError:
                    good = False
                else:
                    self.uncertain_closes.pop()
        if self.scratch is not None and not preserve_scratch:
            try:
                current = set(self.scratch.iterdir())
                if current != set(self.scratch_files):
                    good = False
                else:
                    for path, identity in self.scratch_files.items():
                        if _identity(path.lstat()) != identity:
                            good = False
                            break
                    if good:
                        for path in self.scratch_files:
                            os.unlink(path)
                        os.rmdir(self.scratch)
            except OSError:
                good = False
        self.retained = preserve_scratch or not good or bool(self.uncertain_closes)
        return good


class GitRepository:
    def __init__(self, root: Path, *, git_executable: Path, cancellation=None,
                 execution_source=None, _run: Callable[..., Any] = run_owned):
        # Executable selection is a trusted native/tool-registry input, NEVER
        # a request field. The service neither searches PATH nor installs Git.
        _need(isinstance(root, Path) and root.is_absolute() and isinstance(git_executable, Path)
              and git_executable.is_absolute(), "invalid-input")
        self.root = root.resolve(strict=True)
        self.git_executable = git_executable
        self.cancellation = cancellation
        self.execution_source = execution_source
        self._run = _run
        self._key = object()
        self._retained: list[_IndexTransaction] = []
        self._unknown = False
        self._active_sessions: list[_Session] = []
        self._retained_sessions: list[_Session] = []

    def _finish_sessions(self, uncertain: bool) -> bool:
        if uncertain:
            self._unknown = True
            self._retained_sessions.extend(self._active_sessions)
            self._active_sessions.clear()
            return False
        while self._active_sessions:
            session = self._active_sessions.pop(0)
            try:
                good = session.frozen is None or session.frozen.close()
            except BaseException:
                self._unknown = True
                self._retained_sessions.append(session)
                self._retained_sessions.extend(self._active_sessions)
                self._active_sessions.clear()
                raise
            if not good:
                self._unknown = True
                self._retained_sessions.append(session)
                self._retained_sessions.extend(self._active_sessions)
                self._active_sessions.clear()
                return False
        return True

    def _session(self) -> _Session:
        _need(not self._unknown, "unknown")
        session = _Session(self)
        self._active_sessions.append(session)
        session.discover()
        return session

    @_session_boundary
    def observe(self) -> Observation:
        return self._session().snapshot().public

    @staticmethod
    def _expected(snapshot: _Snapshot, revision: str) -> None:
        _need(type(revision) is str and _REVISION.fullmatch(revision) is not None, "invalid-input")
        _need(snapshot.public.revision == revision, "stale-observation")

    @_session_boundary
    def diff(self, paths: list[str] | tuple[str, ...], *, staged: bool, expected_revision: str) -> Diff:
        paths = _paths(paths)
        _need(type(staged) is bool, "invalid-input")
        session = self._session()
        before = session.snapshot()
        self._expected(before, expected_revision)
        session.validate_paths(paths, before, staging=False)
        if any(_sensitive_path(path) for path in paths):
            return Diff(expected_revision, staged, paths, None, "sensitive-content")
        if not staged and any(path not in before.entries and
                              any(row.path == path and row.index == "?" for row in before.public.changes)
                              for path in paths):
            return Diff(expected_revision, staged, paths, None, "untracked")
        args = ["diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames", "--src-prefix=a/", "--dst-prefix=b/"]
        if staged:
            args.append("--cached")
        args += ["--", *paths]
        _, body = session.git(args, limit=MAX_DIFF_BYTES)
        self._expected(session.snapshot(), expected_revision)
        if _SECRET.search(body):
            return Diff(expected_revision, staged, paths, None, "sensitive-content")
        try:
            text = body.decode("utf-8", "strict")
        except UnicodeError:
            return Diff(expected_revision, staged, paths, None, "non-text")
        if any(ord(c) < 32 and c not in "\n\t\r" or ord(c) == 127 for c in text):
            return Diff(expected_revision, staged, paths, None, "non-text")
        return Diff(expected_revision, staged, paths, text, None)

    @_session_boundary
    def _prepare(self, action: str, paths: list[str] | tuple[str, ...], expected_revision: str) -> GitPlan:
        _need(not self._retained, "recovery-required")
        paths = _paths(paths)
        session = self._session()
        snapshot = session.snapshot()
        self._expected(snapshot, expected_revision)
        self._policy(snapshot, action)
        selected = session.validate_paths(paths, snapshot, staging=action == "stage")
        if action == "unstage":
            _need(all(path in snapshot.entries or any(row.path == path and row.index == "D"
                      for row in snapshot.public.changes) for path in paths), "unsupported-path")
        return GitPlan(action, paths, self._key, snapshot, selected)

    def prepare_stage(self, paths: list[str] | tuple[str, ...], *, expected_revision: str) -> GitPlan:
        return self._prepare("stage", paths, expected_revision)

    def prepare_unstage(self, paths: list[str] | tuple[str, ...], *, expected_revision: str) -> GitPlan:
        return self._prepare("unstage", paths, expected_revision)

    @staticmethod
    def _policy(snapshot: _Snapshot, action: str) -> None:
        _need(not any(entry.stage != 0 for values in snapshot.entries.values() for entry in values), "conflicts")
        for reason in snapshot.public.restrictions:
            if reason != "required-signing" or action == "commit":
                raise GitError(reason)

    @_session_boundary
    def prepare_commit(self, message: str, identity: CommitIdentity, *, expected_revision: str) -> GitPlan:
        _need(not self._retained, "recovery-required")
        _need(type(message) is str and 1 <= len(message.encode("utf-8")) <= 4096 and bool(message.strip())
              and not any(ord(c) < 32 and c not in "\n\t" or ord(c) == 127 for c in message), "invalid-input")
        _need(_SECRET.search(message.encode("utf-8")) is None, "sensitive-content")
        _need(type(identity) is CommitIdentity, "invalid-input")
        identity.validate()
        session = self._session()
        snapshot = session.snapshot()
        self._expected(snapshot, expected_revision)
        self._policy(snapshot, "commit")
        _need(snapshot.public.branch is not None, "unsupported-repository")
        # Every staged change is named in the review, including a staged file
        # that was not selected/staged through MRK. Never commit -- <paths>.
        paths = tuple(row.path for row in snapshot.public.changes if row.index not in (" ", "?", "!"))
        _need(bool(paths), "nothing-staged")
        _paths(paths)
        for values in snapshot.entries.values():
            _need(all(entry.mode in ("100644", "100755") for entry in values), "unsupported-path")
        for path in paths:
            _need(not _sensitive_path(path), "sensitive-content")
            for entry in snapshot.entries.get(path, ()):
                _, body = session.git(["cat-file", "blob", entry.oid], limit=MAX_FILE_BYTES)
                _need(_SECRET.search(body) is None, "sensitive-content")
        self._expected(session.snapshot(), expected_revision)
        return GitPlan("commit", paths, self._key, snapshot, {}, message, identity)

    def _index_transaction(self, session: _Session, current: _Snapshot) -> _IndexTransaction:
        # Internal closed facets may strengthen publication checks; ordinary
        # GitRepository behavior and its original transaction stay unchanged.
        return _IndexTransaction(session, current)

    @_session_boundary
    def apply(self, plan: GitPlan, owner: MutationOwner) -> MutationResult:
        _need(not self._retained, "recovery-required")
        _need(type(plan) is GitPlan and plan._key is self._key and not plan._used, "already-used")
        operation_id = _text(owner.operation_id, 128)
        revision = plan._snapshot.public.revision
        owner.check_current(self.root, plan.action, revision)
        session = self._session()
        current = session.snapshot()
        self._expected(current, revision)
        self._policy(current, plan.action)
        if plan.action != "commit":
            _need(session.validate_paths(plan.paths, current, staging=plan.action == "stage") == plan._selected,
                  "stale-observation")
        plan._used = True
        transaction = self._index_transaction(session, current)
        intent = None
        observation = None
        state, settlement, reason = "failed", "settled", None
        uncertain = False
        preserve_scratch = False
        try:
            transaction.acquire()
            assert transaction.index is not None
            if plan.action == "stage":
                session.git(["add", "--all", "--", *plan.paths], index=transaction.index)
            elif plan.action == "unstage":
                if current.public.head is None:
                    session.git(["update-index", "--force-remove", "--", *plan.paths], index=transaction.index)
                else:
                    session.git(["restore", "--staged", "--source=" + current.public.head, "--", *plan.paths],
                                index=transaction.index)
            else:
                _need(plan.action == "commit")
            transaction.remember_candidate()
            _, raw = session.git(["ls-files", "--stage", "-z"], index=transaction.index)
            candidate_entries = _entries(raw)
            if plan.action != "commit":
                unrelated = set(current.entries) | set(candidate_entries)
                _need(all(current.entries.get(path) == candidate_entries.get(path)
                          for path in unrelated - set(plan.paths)), "recovery-required")
                _need(session.validate_paths(plan.paths, current, staging=plan.action == "stage") == plan._selected,
                      "stale-observation")
                candidate_stamp, _ = _read(transaction.index, MAX_INDEX_BYTES)
                intent = PublicationIntent(plan.action, revision, current.public.branch, current.public.head,
                    current.index_stamp.digest, candidate_stamp.digest, None)
                transaction.check_original()
                owner.check_current(self.root, plan.action, revision)
                owner.record_intent(intent)
                transaction.publish_index()
            else:
                _need(candidate_entries == current.entries, "stale-observation")
                _, tree = session.git(["write-tree"], index=transaction.index, limit=128)
                transaction.remember_candidate()
                args = ["commit-tree", _oid(tree)]
                if current.public.head is not None:
                    args += ["-p", current.public.head]
                assert plan._message is not None and plan._identity is not None
                args += ["-m", plan._message]
                _, commit = session.git(args, index=transaction.index, identity=plan._identity, limit=128)
                commit_id = _oid(commit)
                intent = PublicationIntent("commit", revision, current.public.branch, current.public.head,
                    current.index_stamp.digest, None, commit_id)
                transaction.check_original()
                owner.check_current(self.root, plan.action, revision)
                owner.record_intent(intent)
                transaction.check_original()
                assert current.public.branch is not None
                transaction.release_head_lock()
                transaction.check_original()
                session.git(["update-ref", "--no-deref", "-m", "MRK: record reviewed staged changes",
                             current.public.branch, commit_id, current.public.head or "0" * len(commit_id)], limit=1024)
                # A positive exact command receipt and exact readback are BOTH
                # required. A later ref read cannot settle an unknown producer.
                _need(session.head() == (commit_id, current.public.branch), "recovery-required")
                assert session.git_dir is not None
                _need(_read(session.git_dir / "index", MAX_INDEX_BYTES)[0] == current.index_stamp,
                      "recovery-required")
                _need(session.operation_markers() == current.operations, "recovery-required")
            state = "succeeded"
        except ProcessError as error:
            uncertain = error.fatal
            settlement = "unknown" if uncertain else "settled"
            state = "unknown" if uncertain else "recovery-required" if intent is not None else "failed"
            reason = "unknown" if uncertain else "recovery-required" if intent is not None else "command-failed"
            if not uncertain and transaction.index is not None:
                try:
                    transaction.remember_candidate()
                except (GitError, OSError):
                    preserve_scratch = True
        except GitError as error:
            state = "recovery-required" if intent is not None else "failed"
            reason = error.reason
        except BaseException:
            # Cancellation or an unexpected original-owner failure is not a
            # command receipt. Keep the lock/scratch owner instead of unwinding
            # an automatic TemporaryDirectory over a possibly running child.
            self._retained.append(transaction)
            self._unknown = True
            transaction.retained = True
            raise
        if uncertain:
            self._retained.append(transaction)
            self._unknown = True
            transaction.retained = True
        else:
            try:
                closed = transaction.close(preserve_scratch=preserve_scratch)
            except BaseException:
                self._retained.append(transaction)
                self._unknown = True
                transaction.retained = True
                raise
            if transaction.uncertain_closes:
                state, reason, settlement = "unknown", "unknown", "unknown"
                self._unknown = True
                self._retained.append(transaction)
            if not closed:
                if not transaction.uncertain_closes:
                    state, reason = "recovery-required", "recovery-required"
                    self._retained.append(transaction)
            elif transaction.retained:
                self._retained.append(transaction)
            if state == "succeeded":
                try:
                    observation = session.snapshot().public
                except ProcessError as error:
                    if error.fatal:
                        state, reason, settlement = "unknown", "unknown", "unknown"
                        self._unknown = True
                        self._retained.append(transaction)
                    else:
                        state, reason = "recovery-required", "recovery-required"
                except (GitError, OSError):
                    state, reason = "recovery-required", "recovery-required"
        return MutationResult(operation_id, plan.action, state, settlement, reason, observation, intent)

    @_session_boundary
    def reconcile(self, intent: PublicationIntent) -> str:
        """Read-only classification; NOT owner settlement, retry or rollback.

        Root retains its durable operation and original producer finality. In
        particular, expected-old/absence never proves a timed-out send unsent.
        """
        _need(type(intent) is PublicationIntent, "invalid-input")
        session = self._session()
        observation = session.snapshot()
        if intent.action == "commit":
            if observation.public.branch == intent.expected_ref and observation.public.head == intent.candidate_commit:
                return "candidate-observed"
            if observation.public.branch == intent.expected_ref and observation.public.head == intent.expected_head:
                return "previous-observed"
        elif observation.index_stamp.digest == intent.candidate_index:
            return "candidate-observed"
        elif observation.index_stamp.digest == intent.expected_index:
            return "previous-observed"
        return "changed"
