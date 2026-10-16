"""Owned local Git/input observations for preparation, NEVER Store authority.

This narrow source owner borrows the existing exclusive project invocation and
checked-file/process owners. It does not build, write a journal, authenticate an
artifact, mint consent, or bypass the CI mutation guard. Its observation/draft
remains DATA after the scope closes. A future candidate owner must retain this
scope across its build and compose these finite resources with its own budget.

Initially supported: ordinary full SHA-1 repositories, regular tracked files,
normal index entries, and the closed non-executable local configuration below.
Linked/sparse worktrees, submodules, filters, alternate objects and redirected
configuration are refused. This detects persistent changes under cooperative
project exclusion, not malicious same-user ABA or an atomic checkout snapshot.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import sys
import threading
import time

from .build_inputs import InvocationCustody
from .cancellation import CleanupScope
from .checked_files import _Reader, _Policy, _Node, _directory_identity, _file_identity
from .config import MAX_CONFIG_BYTES, MAX_VERSION_BYTES, ReleaseConfig, parse_config_text
from .discovery import GitContext
from .errors import ConfigurationError, ValidationError
from .local_release_intent import LocalStorePolicy
from .owned_process import ProcessError, fatal_lifetime_error, run_owned

MAX_GIT_BYTES = 2 << 20
MAX_TRACKED = 32768
MAX_CALLS = 12
MAX_HELD = 96
CONFIG_PATH = "release/mobile-release.json"
_ERROR = "Local release source could not be verified"
_REASONS = frozenset(("owner", "path", "input", "repository", "configuration", "index",
                      "source", "dirty", "changed", "command", "deadline", "budget", "closed"))
_SAFE_CONFIG = frozenset(("core.repositoryformatversion", "core.filemode", "core.bare",
    "core.logallrefupdates", "core.ignorecase", "core.precomposeunicode", "core.symlinks",
    "user.name", "user.email", "init.defaultbranch"))


class LocalSourceError(ValidationError):
    def __init__(self, reason):
        assert reason in _REASONS
        self.reason = reason
        super().__init__(_ERROR)


def _now():
    return time.monotonic()


def _need(value, reason):
    if not value:
        raise LocalSourceError(reason)


def _relative(value):
    _need(type(value) is str and 0 < len(value.encode("utf-8")) <= 1024
          and "\\" not in value and "\x00" not in value
          and all(part not in ("", ".", "..", ".git") and len(part.encode("utf-8")) <= 255
                  for part in value.split("/")), "path")
    return value


def _oid(body):
    _need(type(body) is bytes and re.fullmatch(rb"[0-9a-f]{40}\n", body) is not None, "source")
    return body[:-1].decode("ascii")


def _nul(body):
    _need(type(body) is bytes and len(body) <= MAX_GIT_BYTES
          and (not body or body.endswith(b"\0")), "command")
    return body[:-1].split(b"\0") if body else []


def _entries(body, *, index):
    result = {}
    for row in _nul(body):
        header, separator, name = row.partition(b"\t")
        parts = header.split(b" ")
        _need(separator and len(parts) == 3 and parts[0] in (b"100644", b"100755")
              and re.fullmatch(rb"[0-9a-f]{40}", parts[1 if index else 2]) is not None
              and parts[2 if index else 1] == (b"0" if index else b"blob"), "index")
        try:
            _relative(name.decode("utf-8", "strict"))
        except (UnicodeError, LocalSourceError):
            raise LocalSourceError("path") from None
        _need(name not in result and len(result) < MAX_TRACKED, "index")
        result[name] = (parts[0], parts[1 if index else 2])
    _need(bool(result), "index")
    return result


class LocalSourceObservation:
    """Live observation minted only by observe_local_source, not a capability.

    Public GitContext is deliberately DATA. prepare_owned_local_release checks
    this exact original owner's live invocation and reobserves before use.
    """
    def __init__(self, invocation, configuration_bytes, version_bytes, endpoint, execution_source):
        _need(type(invocation) is InvocationCustody and invocation.mode == "build"
              and invocation.project_owner is not None, "owner")
        self.invocation, self.guard = invocation, invocation.cancellation
        self.project = invocation.project_owner
        self.root = invocation.root
        _need(type(self.root) is Path or isinstance(self.root, Path), "path")
        _need(self.root.is_absolute() and ".." not in self.root.parts and 1 < len(self.root.parts) <= 24, "path")
        _need(not stat.S_ISLNK(os.stat(Path("/") / self.root.parts[1], follow_symlinks=False).st_mode), "path")
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.endpoint, self.execution_source = endpoint, execution_source
        self.readers, self.files = [], []
        self.directories = {}
        self._composition = None
        self.calls = self.held = 0
        self.active = False
        self.closed = False
        self.observed = None
        self.configuration_bytes, self.version_bytes = configuration_bytes, version_bytes
        _need(type(configuration_bytes) is bytes and 0 < len(configuration_bytes) <= MAX_CONFIG_BYTES
              and type(version_bytes) is bytes and 0 < len(version_bytes) <= MAX_VERSION_BYTES, "input")
        try:
            self.config = ReleaseConfig(self.root / CONFIG_PATH, self.root,
                                        parse_config_text(configuration_bytes.decode("utf-8")))
            policy = LocalStorePolicy.from_config(self.config)
        except (ConfigurationError, ValidationError, ValueError, UnicodeError):
            raise LocalSourceError("input") from None
        _need(policy.enabled is True, "configuration")
        self.branch = policy.candidate_branch
        self.version_path = _relative(self.config.section("version")["source"])
        _need(self.version_path != CONFIG_PATH, "path")

    def descriptor_quote(self):
        leaves = (CONFIG_PATH, self.version_path, ".git/config", ".git/HEAD", ".git/index",
                  ".git/packed-refs", ".git/refs/heads/" + self.branch)
        paths = {Path("/")}
        for relative in (*leaves, ".git/objects/info", ".git/info", ".git/refs"):
            path = self.root / relative
            paths.update((path, *path.parents))
        _need(len(paths) <= MAX_HELD, "budget")
        return len(paths)

    def _charge(self, count):
        _need(type(count) is int and count >= 0 and self.held + count <= self.descriptor_quote(), "budget")
        self.held += count  # Never credit an unknown open or consuming close.

    def _owner(self):
        _need(self.pid == os.getpid() and self.thread is threading.current_thread()
              and not self.closed and self.invocation.project_owner is self.project, "owner")
        self.invocation.require(root=self.root, cancellation=self.guard,
                                signing_lease=self.invocation.signing_lease)
        self.guard.check()
        _need(_now() < self.endpoint, "deadline")

    def _file(self, relative, limit, expected=None, *, control=False):
        self._owner()
        if control:
            _need(relative.startswith(".git/"), "path")
            _relative(relative[5:])
        else:
            _relative(relative)
        path = self.root / relative
        if not self.readers:
            self._charge(len(path.parts))
            reader = _Reader(self.guard)
            self.readers.append(reader)  # Original fallback before any open.
            node = reader.acquire(path, _Policy(False, 1, limit), None)
            self.directories.update((item.canonical, item) for item in reader.nodes if item.directory)
        else:
            reader = self.readers[0]
            reader.terminal()
            parent = self.directories[self.root]
            for part in path.relative_to(self.root).parts[:-1]:
                parent = self._directory(reader, parent, part)
            info = reader._stat(parent.slot, path.name)
            _need(stat.S_ISREG(info.st_mode) and 1 <= info.st_size <= limit
                  and info.st_uid == os.geteuid() and info.st_nlink == 1
                  and not info.st_mode & 0o022, "input")
            self._charge(1)
            slot = reader._open(path.name, parent=parent.slot, directory=False)
            node = _Node(slot, parent.slot, path.name, path, info, False)
            reader.nodes.append(node)  # Root before any failing identity POST.
            _need(_file_identity(os.fstat(reader._number(slot))) == _file_identity(info)
                  == _file_identity(reader._stat(parent.slot, path.name)), "changed")
        _need(node.observed.st_uid == os.geteuid() and node.observed.st_nlink == 1
              and not node.observed.st_mode & 0o022, "input")
        roots = [item for item in reader.nodes if item.canonical == self.root]
        _need(len(roots) == 1 and _directory_identity(roots[0].observed)
              == _directory_identity(os.fstat(self.project.fd)), "changed")
        body = reader.read(node)
        _need(expected is None or body == expected, "input")
        self.files.append((reader, node, body))
        reader.terminal()
        return reader, node, body

    def _directory(self, reader, parent, name):
        self._owner()
        reader.terminal()
        path = parent.canonical / name
        if path in self.directories:
            node = self.directories[path]
            _need(node.parent is parent.slot and node in reader.nodes, "changed")
            return node
        self._charge(1)
        info = reader._stat(parent.slot, name)
        _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
              and not info.st_mode & 0o022, "repository")
        slot = reader._open(name, parent=parent.slot, directory=True)
        node = _Node(slot, parent.slot, name, parent.canonical / name, info, True)
        reader.nodes.append(node)
        reader.terminal()
        self.directories[path] = node
        return node

    def _unchanged(self):
        self._owner()
        for reader in self.readers:
            reader.terminal()
        for parent, names in self.absent:
            for name in names:
                try:
                    os.stat(name, dir_fd=self.git_reader._number(parent.slot), follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise LocalSourceError("repository")

    def _git(self, arguments, limit=MAX_GIT_BYTES):
        self._unchanged()
        self.calls += 1
        _need(self.calls <= MAX_CALLS, "budget")
        remaining = self.endpoint - _now()
        _need(remaining >= 1, "deadline")
        argv = ["/usr/bin/git", "--no-pager", "--no-replace-objects",
                "--git-dir=" + str(self.root / ".git"), "--work-tree=" + str(self.root),
                "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                "-c", "core.untrackedCache=false", "-c", "core.filemode=true",
                "-c", "core.symlinks=true", "-c", "protocol.allow=never", *arguments]
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
            "GIT_ALLOW_PROTOCOL": "", "GIT_LITERAL_PATHSPECS": "1", "GIT_ATTR_NOSYSTEM": "1", "GIT_PAGER": "cat"}
        timeout = min(10, math.floor(remaining))
        candidate = self._composition
        if candidate is not None:
            candidate._arm_source(self, arguments, timeout, limit)
        try:
            result = run_owned(argv, cwd=self.root, environ=environment, capture=True, text=False,
                timeout=timeout, output_limit=limit, cancellation=self.guard,
                execution_scope=None if self.execution_source is None else self.execution_source.new_scope())
        except BaseException as error:
            if candidate is not None:
                candidate._source_error(self, error)
            raise
        if candidate is not None:
            candidate._source_returned(self, result)
        _need(type(result.returncode) is int and result.returncode == 0 and result.args == argv and type(result.stdout) is bytes and type(result.stderr) is bytes
              and result.stderr == b"" and len(result.stdout) <= limit, "command")
        self._unchanged()
        return result.stdout

    def _configuration(self):
        # --no-includes is important: inspect the local keys without following
        # arbitrary include files. No status/diff/checkout/filter runs yet.
        rows = self._git(["config", "--local", "--no-includes", "--null", "--list"], 65536)
        keys = set()
        for row in _nul(rows):
            key, separator, value = row.partition(b"\n")
            _need(separator and key and len(key) <= 1024, "configuration")
            try:
                key = key.decode("ascii").lower()
            except UnicodeError:
                raise LocalSourceError("configuration") from None
            allowed = key in _SAFE_CONFIG or re.fullmatch(r"(?:remote\.[A-Za-z0-9_-]+\.(?:url|fetch)|branch\..+\.(?:remote|merge))", key)
            _need(allowed and key not in keys, "configuration")
            keys.add(key)
            if key == "core.repositoryformatversion":
                _need(value == b"0", "configuration")
            elif key == "core.bare":
                _need(value == b"false", "configuration")
        _need({"core.repositoryformatversion", "core.bare"} <= keys, "configuration")

    def _capture(self):
        self._configuration()
        # --shared-index-path emits another line for a split index. The only
        # accepted result is exactly the two requested IDs, so no unheld shared
        # index can affect later flags/status. No stdin/batch executor is added.
        ids = self._git(["rev-parse", "--shared-index-path", "HEAD", "HEAD^{tree}"], 1024).splitlines(keepends=True)
        _need(len(ids) == 2, "index")
        head, tree = (_oid(row) for row in ids)
        index = _entries(self._git(["ls-files", "--stage", "-z"]), index=True)
        flags = _nul(self._git(["ls-files", "-v", "-z"]))
        _need(len(flags) == len(index) and all(row.startswith(b"H ") for row in flags)
              and {row[2:] for row in flags} == set(index), "index")
        tracked = _entries(self._git(["ls-tree", "-r", "-z", "--full-tree", head]), index=False)
        _need(index == tracked, "dirty")
        # Git blob identity binds the exact retained saved bytes to HEAD.
        # Literal names select rows, not pathspec/revision parsing or filters.
        for name, expected in ((CONFIG_PATH, self.configuration_bytes), (self.version_path, self.version_bytes)):
            row = tracked.get(name.encode("utf-8"))
            _need(row is not None and row[0] == b"100644", "input")
            actual = hashlib.sha1(b"blob " + str(len(expected)).encode("ascii") + b"\0" + expected).hexdigest().encode("ascii")
            _need(actual == row[1], "input")
        self._clean()
        metadata = getattr(self, "_metadata_owner", None)
        if metadata is not None:
            from .local_release_metadata import LocalMetadataSource
            _need(type(metadata) is LocalMetadataSource and metadata.source is self, "owner")
            metadata._accept_tracked(self, tracked)
        return GitContext(None, None, head, tree, "refs/heads/" + self.branch, self.branch, False)

    def acquire(self):
        self._owner()
        self._file(CONFIG_PATH, MAX_CONFIG_BYTES, self.configuration_bytes)
        self._file(self.version_path, MAX_VERSION_BYTES, self.version_bytes)
        self.git_reader, config_node, _ = self._file(".git/config", 65536, control=True)
        git = next(node for node in self.git_reader.nodes if node.canonical == self.root / ".git")
        _need(git.observed.st_uid == os.geteuid() and not git.observed.st_mode & 0o022, "repository")
        objects = self._directory(self.git_reader, git, "objects")
        info = self._directory(self.git_reader, objects, "info")
        git_info = self._directory(self.git_reader, git, "info")
        self.absent = [(git, ("commondir", "config.worktree", "shallow")),
                       (info, ("alternates", "http-alternates")), (git_info, ("grafts", "attributes"))]
        refs = self._directory(self.git_reader, git, "refs")
        self.absent.append((refs, ("replace",)))
        parts = ["heads", *_relative(self.branch).split("/")]
        for part in parts[:-1]:
            # pack-refs may remove an empty nested branch directory. Hold the
            # first missing name against its original parent, not a recreated
            # loose-ref path. Any later ancestor creation still vetoes use.
            try:
                os.stat(part, dir_fd=self.git_reader._number(refs.slot), follow_symlinks=False)
            except FileNotFoundError:
                self.absent.append((refs, (part,)))
                refs = None
                break
            refs = self._directory(self.git_reader, refs, part)
        controls = [(git, "packed-refs", ".git/packed-refs", MAX_GIT_BYTES)]
        if refs is not None:
            controls.insert(0, (refs, parts[-1], ".git/refs/heads/" + self.branch, 128))
        for parent, name, relative, cap in controls:
            try:
                os.stat(name, dir_fd=self.git_reader._number(parent.slot), follow_symlinks=False)
            except FileNotFoundError:
                self.absent.append((parent, (name,)))
            else:
                self._file(relative, cap, control=True)
        _, _, head = self._file(".git/HEAD", 1024, control=True)
        _need(head == ("ref: refs/heads/" + self.branch + "\n").encode("utf-8"), "source")
        self._file(".git/index", MAX_GIT_BYTES, control=True)
        self._unchanged()
        self.observed = self._capture()
        self.active = True

    def _clean(self):
        _need(self._git(["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"]) == b"", "dirty")

    def check(self):
        _need(self.active and not self.closed, "closed")
        # Config, HEAD, selected loose/packed refs and index cannot change or
        # switch names while their held originals/absence guards remain equal.
        # Recheck only working files; repeating the same tree/config queries
        # would add processes without improving that source binding.
        self._clean()
        return self.observed

    def _close(self):
        self.active, self.closed = False, True
        first = None
        for reader in reversed(self.readers):
            try:
                reader.close()
            except BaseException as error:
                if first is None:
                    first = error
        if first is not None:
            raise first

    def _fork_close(self):
        for reader in reversed(self.readers):
            reader.after_fork_child()


@contextmanager
def _retain_source(owner):
    # Shared original scope; the candidate constructs an owner with its exact
    # borrowed work endpoint rather than extending the public short timeout.
    scope = CleanupScope(owner.guard, owner._close, owns_cancellation=False,
                         fork_cleanup=owner._fork_close, first_primary=True)
    try:
        try:
            with scope:
                owner.acquire()
                yield owner
                owner.check()
        finally:
            scope.__exit__(*sys.exc_info())
        for reader in owner.readers:
            reader.assert_closed()
        owner.guard.check()
    except BaseException as error:
        fatal = fatal_lifetime_error(error, "Local source original custody did not settle")
        if fatal is not None:
            raise fatal from None
        if isinstance(error, (OSError, UnicodeError)) or isinstance(error, ValidationError) and not isinstance(error, (LocalSourceError, ProcessError)):
            raise LocalSourceError("input") from None
        raise


@contextmanager
def observe_local_source(invocation, *, configuration_bytes, version_bytes,
                         execution_source=None, timeout=60):
    """Short preparation DATA only; no durable intent or Store authority."""
    _need(type(timeout) is int and 1 <= timeout <= 120, "deadline")
    owner = LocalSourceObservation(invocation, configuration_bytes, version_bytes,
                                   _now() + timeout, execution_source)
    with _retain_source(owner) as held:
        yield held
