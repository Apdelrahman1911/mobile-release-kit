"""Finite external-file observation and consumption, not pathname authority.

Only the two actual Darwin root aliases are supported. Every other component is
opened without following links, from an original root descriptor. Bytes (or a
borrowed owner's immutable snapshot) leave this scope only after terminal source
observations and all descriptor/handler cleanup. A diagnostic Path grants no
permission to reopen its original later.
"""
from __future__ import annotations

import os
import stat
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Literal, TypeVar

from .cancellation import CleanupScope, DefaultCancellation, cancellation_owner, _mark_fork_unsafe
from .errors import ValidationError
from .credential_policy import (CREDENTIALS_FILE_MAX_BYTES, PRIVATE_SMALL_MAX_BYTES,
                                PRIVATE_GENERAL_MAX_BYTES)
from .owned_process import ProcessCleanupError
from ._profile_callers import fatal_cancellation_error
from .toolchain_policy import BUNDLETOOL_MAX_BYTES, BUNDLETOOL_SHA256, BUNDLETOOL_VERSION

if TYPE_CHECKING:
    from .build_inputs import FiniteScratch, InputSnapshot


ExternalKind = Literal["credentials-file", "private-small", "private-general", "public-tool"]
PrivateKind = Literal["credentials-file", "private-small", "private-general"]

_READ_CHUNK = 1024 * 1024
_MAX_COMPONENTS = 128
_MAX_PATH_BYTES = 4096
_RESOURCE_ERROR = "external input descriptor or cancellation cleanup is unconfirmed"
_T = TypeVar("_T")


@dataclass(frozen=True)
class _Policy:
    private: bool
    minimum: int
    maximum: int | None


_POLICIES = {
    "credentials-file": _Policy(True, 0, CREDENTIALS_FILE_MAX_BYTES),
    "private-small": _Policy(True, 1, PRIVATE_SMALL_MAX_BYTES),
    "private-general": _Policy(True, 1, PRIVATE_GENERAL_MAX_BYTES),
    "public-tool": _Policy(False, 0, None),
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _policy(kind: ExternalKind) -> _Policy:
    _require(type(kind) is str and kind in _POLICIES, "unknown external input kind")
    return _POLICIES[kind]


def _absolute(path: Path, *, private: bool) -> Path:
    # Do not use abspath/resolve: either can erase a link/.. traversal before
    # the checked walk sees it. expanduser remains an explicit supported input.
    try:
        path = Path(path).expanduser()
    except (TypeError, ValueError, RuntimeError):
        raise ValidationError("external input path is invalid") from None
    _require(".." not in path.parts, "external input path must not contain parent traversal")
    if not path.is_absolute():
        _require(not private, "private input path must be absolute")
        path = Path.cwd() / path  # One observed cwd anchors a relative public tool.
    _require(path.anchor == "/" and ".." not in path.parts,
             "external input path must have one local filesystem root")
    _require(len(path.parts) <= _MAX_COMPONENTS and
             len(os.fsencode(path)) <= _MAX_PATH_BYTES and "\x00" not in str(path),
             "external input path exceeds its bounded layout")
    return path


def _directory_identity(value: os.stat_result) -> tuple[int, ...]:
    # Sibling creation changes directory timestamps/link counts, not authority.
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def _directory_key(value: os.stat_result) -> tuple[int, int]:
    # Containment and physical roles identify directories, not caller spelling
    # or file hardlinks. Full metadata remains bound by acquisition/terminal checks.
    return value.st_dev, value.st_ino


def _file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (*_directory_identity(value), value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def _protect_directory(role: Path | None, value: os.stat_result) -> None:
    _require(stat.S_ISDIR(value.st_mode), "external input ancestor must be a directory without symbolic links")
    if sys.platform != "darwin":
        return
    # A role is the fixed physical topology matched to the pinned directory,
    # never the input's diagnostic/caller-spelled path.
    if role in (Path("/"), Path("/private"), Path("/private/var")):
        _require(value.st_uid == 0 and not value.st_mode & 0o022,
                 "macOS physical input ancestry is not system protected")
    elif role == Path("/private/tmp"):
        _require(value.st_uid == 0 and (not value.st_mode & 0o022 or bool(value.st_mode & stat.S_ISVTX)),
                 "macOS shared temporary ancestry lacks system ownership or sticky protection")


def _alias_parts(name: str, value: os.stat_result, target: str) -> tuple[str, str]:
    _require(sys.platform == "darwin" and name in ("tmp", "var") and
             stat.S_ISLNK(value.st_mode) and value.st_uid == 0 and
             target in (f"private/{name}", f"/private/{name}"),
             "external input must not traverse an unsupported symbolic link")
    return "private", name


@dataclass
class _Descriptor:
    # The slot is registered before open. Numbers are relinquished BEFORE the
    # sole close attempt; an exception can never authorize a retry of that number.
    number: int | None = None
    state: str = "UNACQUIRED"


@dataclass(frozen=True)
class _Node:
    slot: _Descriptor
    parent: _Descriptor | None
    name: str
    canonical: Path
    observed: os.stat_result
    directory: bool


@dataclass(frozen=True)
class _Alias:
    name: str
    observed: os.stat_result
    target: str


class _Reader:
    """One fixed read/copy's descriptors; no scratch, process or retry owner."""

    def __init__(self, cancellation: DefaultCancellation) -> None:
        self.cancellation = cancellation
        self.pid = os.getpid()
        self.thread = threading.current_thread()
        self.descriptors: list[_Descriptor] = []
        self.nodes: list[_Node] = []
        self.aliases: list[_Alias] = []
        self.root: _Descriptor | None = None

    def _origin(self) -> None:
        if self.pid != os.getpid():
            self.after_fork_child()
            raise ProcessCleanupError("inherited external input reader cannot publish bytes")
        if self.thread is not threading.current_thread():
            raise ProcessCleanupError("external input reader belongs to another thread")

    def _number(self, slot: _Descriptor) -> int:
        self._origin()
        _require(slot.state == "OWNED" and type(slot.number) is int and slot.number >= 0,
                 "external input descriptor is not live")
        return slot.number

    def _open(self, name: str, *, parent: _Descriptor | None, directory: bool) -> _Descriptor:
        self._origin()
        self.cancellation.check()
        slot = _Descriptor()
        self.descriptors.append(slot)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        flags |= os.O_DIRECTORY if directory else os.O_NONBLOCK
        with self.cancellation.deferred(check_on_exit=False):
            slot.state = "ACQUIRING"
            try:
                slot.number = os.open(name, flags, dir_fd=None if parent is None else self._number(parent))
                self._origin()
            except BaseException as error:
                if self.pid != os.getpid():
                    self.after_fork_child()
                    raise
                slot.state = "OWNED" if type(slot.number) is int and slot.number >= 0 else "UNKNOWN"
                if slot.state == "UNKNOWN":
                    self.cancellation._abort(error)
                raise
            if type(slot.number) is not int or slot.number < 0:
                slot.state = "UNKNOWN"
                error = ProcessCleanupError(_RESOURCE_ERROR)
                self.cancellation._abort(error)
                raise error
            slot.state = "OWNED"
        self.cancellation.check()
        return slot

    def after_fork_child(self) -> None:
        if self.pid == os.getpid():
            return
        # Never call the parent's guard/ledger or retry an ambiguous close. A
        # known child copy (including a late positive open return) closes once.
        for slot in self.descriptors:
            if slot.state in ("UNKNOWN", "CLOSING", "INHERITED_UNKNOWN"):
                slot.state = "INHERITED_UNKNOWN"
                _mark_fork_unsafe()
                continue
            if slot.state == "ACQUIRING" and slot.number is None:
                _mark_fork_unsafe()
            slot.state = "INHERITED"
            if type(slot.number) is int and slot.number >= 0:
                number, slot.number = slot.number, None
                slot.state = "INHERITED_UNKNOWN"
                try:
                    os.close(number)
                except BaseException:
                    _mark_fork_unsafe()
                else:
                    slot.state = "INHERITED"

    def close(self) -> None:
        self._origin()
        first: BaseException | None = None
        for slot in reversed(self.descriptors):
            if slot.state in ("UNACQUIRED", "CLOSED"):
                continue
            try:
                if slot.state != "OWNED" or type(slot.number) is not int or slot.number < 0:
                    raise ProcessCleanupError(_RESOURCE_ERROR)
                number, slot.number = slot.number, None
                slot.state = "CLOSING"
                os.close(number)
                slot.state = "CLOSED"
            except BaseException as error:
                slot.state = "UNKNOWN"
                self.cancellation._abort(error)
                if first is None:
                    first = error
        if first is not None:
            if isinstance(first, (KeyboardInterrupt, SystemExit)):
                raise first
            raise ProcessCleanupError(_RESOURCE_ERROR) from None

    def assert_closed(self) -> None:
        self._origin()
        if any(slot.state not in ("UNACQUIRED", "CLOSED") for slot in self.descriptors):
            error = ProcessCleanupError(_RESOURCE_ERROR)
            self.cancellation._abort(error)
            raise error

    def _stat(self, parent: _Descriptor, name: str) -> os.stat_result:
        self.cancellation.check()
        return os.stat(name, dir_fd=self._number(parent), follow_symlinks=False)

    def _physical_role(self, parent: _Descriptor, parent_role: Path | None,
                       observed: os.stat_result) -> Path | None:
        if sys.platform != "darwin":
            return None
        names = (("private",) if parent_role == Path("/") else
                 ("var", "tmp") if parent_role == Path("/private") else ())
        for name in names:
            # Compare only the exact admitted children of an already bound
            # physical parent. No casefold, resolve, or second path walker.
            physical = self._stat(parent, name)
            _require(stat.S_ISDIR(physical.st_mode),
                     "macOS physical input ancestry must be a directory without symbolic links")
            if _directory_key(physical) == _directory_key(observed):
                _require(_directory_identity(physical) == _directory_identity(observed),
                         "macOS physical input ancestry changed during acquisition")
                assert parent_role is not None
                return parent_role / name
        return None

    def _directories(self, parts: tuple[str, ...]) -> tuple[_Descriptor, Path]:
        _require(self.root is not None, "external input root has not been acquired")
        parent, canonical = self.root, Path("/")
        physical: Path | None = Path("/")
        if parts:
            first = self._stat(parent, parts[0])
            if stat.S_ISLNK(first.st_mode):
                target = os.readlink(parts[0], dir_fd=self._number(parent))
                replacement = _alias_parts(parts[0], first, target)
                self.aliases.append(_Alias(parts[0], first, target))
                parts = (*replacement, *parts[1:])
        for name in parts:
            canonical /= name
            observed = self._stat(parent, name)
            role = self._physical_role(parent, physical, observed)
            _protect_directory(role, observed)
            child = self._open(name, parent=parent, directory=True)
            _require(_directory_identity(os.fstat(self._number(child))) == _directory_identity(observed) ==
                     _directory_identity(self._stat(parent, name)),
                     "external input ancestor changed during acquisition")
            self.nodes.append(_Node(child, parent, name, canonical, observed, True))
            if role is not None and name != role.name:
                # The same pinned descriptor also binds the exact physical
                # entry used to select its role, including at terminal checks.
                self.nodes.append(_Node(child, parent, role.name, role, observed, True))
            parent, physical = child, role
        return parent, canonical

    def acquire(self, path: Path, policy: _Policy, project_root: Path | None) -> _Node:
        _require(os.name == "posix" and all(hasattr(os, name) for name in
                 ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK", "O_CLOEXEC")),
                 "external input checking requires supported no-follow descriptor operations")
        root_stat = os.stat("/", follow_symlinks=False)
        _protect_directory(Path("/"), root_stat)
        self.root = self._open("/", parent=None, directory=True)
        _require(_directory_identity(os.fstat(self._number(self.root))) == _directory_identity(root_stat),
                 "external input filesystem root changed")
        self.nodes.append(_Node(self.root, None, "/", Path("/"), root_stat, True))
        project_identity = None
        if policy.private:
            _require(project_root is not None, "private input checking requires its project root")
            project_fd, _project_path = self._directories(project_root.parts[1:])
            project_identity = _directory_key(os.fstat(self._number(project_fd)))
        _require(len(path.parts) > 1, "external input must name a regular file")
        source_start = len(self.nodes)
        parent, directory = self._directories(path.parts[1:-1])
        canonical = directory / path.name
        # Only this input's pinned root/ancestry participates, not the separate
        # project walk. A leaf hardlink outside that ancestry remains supported.
        source_ancestors = (self.nodes[0], *self.nodes[source_start:])
        _require(project_identity is None or all(_directory_key(node.observed) != project_identity
                                                for node in source_ancestors),
                 "private input must live outside the project repository")
        observed = self._stat(parent, path.name)
        _require(stat.S_ISREG(observed.st_mode), "external input must be a regular file without symbolic links")
        _require(not policy.private or not stat.S_IMODE(observed.st_mode) & 0o077,
                 "private input must not be accessible by group or others")
        _require(observed.st_size >= policy.minimum and
                 (policy.maximum is None or observed.st_size <= policy.maximum),
                 "external input is empty or exceeds its safety size limit")
        leaf = self._open(path.name, parent=parent, directory=False)
        _require(_file_identity(os.fstat(self._number(leaf))) == _file_identity(observed) ==
                 _file_identity(self._stat(parent, path.name)),
                 "external input changed during acquisition")
        node = _Node(leaf, parent, path.name, canonical, observed, False)
        self.nodes.append(node)
        return node

    def read(self, node: _Node) -> bytes:
        content = bytearray()
        size = node.observed.st_size
        while True:
            self.cancellation.check()
            block = os.read(self._number(node.slot), min(_READ_CHUNK, size - len(content) + 1))
            if not block:
                break
            content.extend(block)
            _require(len(content) <= size, "external input grew during its bounded read")
        _require(len(content) == size, "external input shortened during its bounded read")
        return bytes(content)

    def terminal(self) -> None:
        # Compare entries through their original parent descriptors, not a fresh
        # resolve/open of the original. atime and shared-directory timestamps do
        # not affect equality; file content metadata and every mode/owner do.
        for node in reversed(self.nodes):
            self.cancellation.check()
            identity = _directory_identity if node.directory else _file_identity
            entry = (os.stat("/", follow_symlinks=False) if node.parent is None
                     else self._stat(node.parent, node.name))
            _require(identity(os.fstat(self._number(node.slot))) == identity(node.observed) == identity(entry),
                     "external input or its ancestry changed during observation")
        _require(self.root is not None, "external input root has not been acquired")
        for alias in self.aliases:
            self.cancellation.check()
            _require(_file_identity(self._stat(self.root, alias.name)) == _file_identity(alias.observed) and
                     os.readlink(alias.name, dir_fd=self._number(self.root)) == alias.target,
                     "macOS system input alias changed during observation")


def _consume(path: Path, policy: _Policy, *, project_root: Path | None,
             cancellation: DefaultCancellation | None,
             action: Callable[[_Reader, _Node], _T]) -> _T:
    path = _absolute(path, private=policy.private)
    if policy.private:
        _require(project_root is not None, "private input checking requires its project root")
        project_root = _absolute(project_root, private=True)
    guard, owns = cancellation_owner(cancellation, ProcessCleanupError, _RESOURCE_ERROR)
    reader = _Reader(guard)
    scope = CleanupScope(guard, reader.close, owns_cancellation=owns,
                         fork_cleanup=reader.after_fork_child, first_primary=True)
    try:
        try:
            with scope:
                if owns:
                    guard.install()
                    guard.activate()
                guard.check()
                node = reader.acquire(path, policy, project_root)
                value = action(reader, node)
                reader.terminal()
        finally:
            scope.__exit__(*sys.exc_info())
        reader.assert_closed()
        guard.check()  # Borrowed cancellation may have arrived during cleanup.
        return value
    except BaseException as primary:
        fatal = fatal_cancellation_error(primary, guard, _RESOURCE_ERROR)
        if fatal is not None:
            raise fatal from None
        if isinstance(primary, (OSError, NotImplementedError)):
            raise ValidationError("external input or required ancestry could not be inspected") from None
        raise


def read_external_bytes(path: Path, *, kind: PrivateKind, project_root: Path,
                        cancellation: DefaultCancellation | None = None) -> bytes:
    policy = _policy(kind)
    _require(policy.private, "external byte reading requires an explicit private input kind")
    return _consume(path, policy, project_root=project_root, cancellation=cancellation,
                    action=lambda reader, node: reader.read(node))


def inspect_external_path(path: Path, *, kind: ExternalKind, project_root: Path | None,
                          cancellation: DefaultCancellation | None = None) -> Path:
    """Diagnostic observation only; a returned Path is NEVER reopen authority."""
    return _consume(path, _policy(kind), project_root=project_root, cancellation=cancellation,
                    action=lambda _reader, node: node.canonical)


def read_readback_bytes(path: Path, *, cancellation: DefaultCancellation) -> bytes:
    """Read a caller-owned online output; never acquire deletion ownership.

    Outputs may be inside the application, unlike external credentials. The
    input policies stay unchanged: this fixed internal policy reuses their
    checked walk, bounded read and original terminal/descriptor settlement.
    """
    absolute = _absolute(path, private=True)

    def read(reader: _Reader, node: _Node) -> bytes:
        observed = node.observed
        _require(observed.st_uid == os.geteuid() and stat.S_IMODE(observed.st_mode) == 0o600
                 and observed.st_nlink == 1, "online readback must be a private singly linked file")
        return reader.read(node)

    return _consume(absolute, _Policy(False, 1, PRIVATE_SMALL_MAX_BYTES), project_root=None,
                    cancellation=cancellation, action=read)


def copy_bundletool(path: Path, *, scratch: FiniteScratch, maximum_bytes: int,
                    expected_sha256: str) -> InputSnapshot:
    """Authenticate one fixed public tool while streaming into its live owner."""
    _require(type(maximum_bytes) is int and maximum_bytes == BUNDLETOOL_MAX_BYTES and
             type(expected_sha256) is str and expected_sha256 == BUNDLETOOL_SHA256,
             "bundletool copy requires the pinned version, digest and artifact-derived bound")
    # Runtime admission is local to the call, not an import-time scratch effect
    # or a dependency from the low-level native/profile authority graph.
    from .build_inputs import FiniteScratch

    _require(type(scratch) is FiniteScratch, "bundletool copy requires its actual finite scratch owner")

    def copy(reader: _Reader, node: _Node) -> InputSnapshot:
        snapshot = scratch.copy_from_fd("bundletool", reader._number(node.slot),
                                        maximum_bytes=maximum_bytes, expected_sha256=expected_sha256)
        _require(snapshot.size == node.observed.st_size and snapshot.sha256 == BUNDLETOOL_SHA256,
                 "bundletool snapshot differs from its selected input")
        return snapshot

    snapshot = _consume(path, _Policy(False, 1, BUNDLETOOL_MAX_BYTES), project_root=None,
                        cancellation=scratch.cancellation, action=copy)
    scratch.require(snapshot)  # Only after source terminal observations/closes.
    return snapshot
