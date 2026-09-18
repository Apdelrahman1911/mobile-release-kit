"""A recoverable local init transaction, not a general filesystem database.

Only Linux/macOS local filesystems with flock, fsync and atomic exclusive rename
are supported for mutation. Imports/capability checks are lazy so preview and
unrelated commands remain portable. A lock coordinates init, not hostile peers
with the same UID or arbitrary namespace/old-file-descriptor manipulation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
import uuid
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

from .errors import ValidationError
from .workflow_payloads import GITHUB_WORKFLOWS as WORKFLOWS

PREPARING = ".mobile-release-init-prepare"
READY = ".mobile-release-init"
CLEANUP = ".mobile-release-init-cleanup"
STATE_NAMES = (PREPARING, READY, CLEANUP)
METADATA_PREPARING = ".mobile-release-metadata-text-prepare"
METADATA_READY = ".mobile-release-metadata-text"
METADATA_CLEANUP = ".mobile-release-metadata-text-cleanup"
METADATA_STATE_NAMES = (METADATA_PREPARING, METADATA_READY, METADATA_CLEANUP)
# Admission/exclusion only. Legacy recovery must NEVER treat another domain's
# empty or header.tmp-only preparation as its own cleanup candidate.
ALL_STATE_NAMES = (*STATE_NAMES, *METADATA_STATE_NAMES)
IGNORE_LINES = (".mobile-release/", *(name + "/" for name in ALL_STATE_NAMES))
MAX_FILES = 256
MAX_FILE_BYTES = 8 * 1024**2
MAX_TOTAL_BYTES = 64 * 1024**2
MAX_CONTROL_BYTES = 512 * 1024
MAX_DIRECTORY_ENTRIES = 100_000
CONTROLS = {"header.json", "header.tmp", "plan.json", "plan.tmp",
            "commit.pending", "rollback.pending", "COMMITTED", "ROLLED_BACK"}
PROBES = {"probe-a", "probe-b", "probe-c"}


class TypedEditProfile(Enum):
    """Three internal native domains, never a caller-supplied path inventory."""

    CONFIGURATION = "configuration"
    GITHUB_WORKFLOWS = "github-workflows"
    METADATA_TEXT = "metadata-text"

    @property
    def paths(self) -> tuple[str, ...]:
        if self is TypedEditProfile.CONFIGURATION:
            return ("release/mobile-release.json", ".gitignore")
        if self is TypedEditProfile.GITHUB_WORKFLOWS:
            return tuple(path for _, path in WORKFLOWS)
        raise ValueError("metadata targets require the original configuration-bound descriptor")

    @property
    def observation_limits(self) -> tuple[int, ...]:
        if self is TypedEditProfile.CONFIGURATION:
            return (512 * 1024, 1024 * 1024)
        if self is TypedEditProfile.GITHUB_WORKFLOWS:
            return (1024 * 1024,) * 4
        raise ValueError("metadata observations require the original target descriptor")

    @property
    def payload_limits(self) -> tuple[int, ...]:
        if self is TypedEditProfile.CONFIGURATION:
            return self.observation_limits
        if self is TypedEditProfile.GITHUB_WORKFLOWS:
            return (16 * 1024,) * 4
        raise ValueError("metadata payloads require the original target descriptor")

    @property
    def directories(self) -> tuple[str, ...]:
        if self is TypedEditProfile.CONFIGURATION:
            return ("release",)
        if self is TypedEditProfile.GITHUB_WORKFLOWS:
            return (".github", ".github/workflows")
        raise ValueError("metadata directories require the original target descriptor")


class InitInterrupted(KeyboardInterrupt):
    """An interrupt with an explicit rollback/recovery outcome."""


class InitConflict(ValidationError):
    """An observed user/namespace change must not be adopted by automatic retry."""


@dataclass(frozen=True)
class InitApplyOutcome:
    """Provisional original-transaction facts, never process finality.

    A COMMITTED decision is irreversible even when a following fsync fails.
    Only clean durability/cleanup, settled resources and reason=none may be a
    successful save.  This type has no native imports on the passive path.
    """

    effect: str
    journal: str
    resources: str
    reason: str


class InitOperationFailure(BaseException):
    """Exact typed native carrier; private primary is never serialized."""

    def __init__(self, outcome: InitApplyOutcome, primary: BaseException | None = None):
        super().__init__("configuration transaction did not complete")
        self.outcome = outcome
        self._primary = primary


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(f"init transaction: {message}")


def _key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def is_state_name(value: str) -> bool:
    return _key(value) in ALL_STATE_NAMES


def validate_paths(paths: list[str]) -> None:
    """Validate files and every implicit directory, including portable aliases."""
    _require(0 < len(paths) <= MAX_FILES, "invalid destination count")
    components: dict[str, tuple[str, bool]] = {}
    for name in paths:
        try:
            parts = name.split("/")
            valid = len(name.encode("utf-8")) <= 4096 and len(parts) <= 64 and all(
                part not in {"", ".", ".."} and len(part.encode("utf-8")) <= 255
                and not part.endswith((" ", "."))
                and not any(ord(c) < 32 or ord(c) == 127 or c in "\\:" for c in part)
                for part in parts
            )
        except (AttributeError, UnicodeError):
            valid = False
        _require(valid, "unsafe destination path")
        _require(_key(parts[0]) not in {_key(n) for n in (*ALL_STATE_NAMES, ".git")},
                 "destination uses a reserved transaction or Git path")
        for count in range(1, len(parts) + 1):
            path = "/".join(parts[:count])
            value = (path, count < len(parts))
            previous = components.get(_key(path))
            _require(previous is None or (value[1] and previous == value),
                     "duplicate init destination, portable alias, or file/ancestor conflict")
            components[_key(path)] = value
    _require(sum(is_dir for _, is_dir in components.values()) <= MAX_FILES,
             "too many destination directories")


def _json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        _require(key not in result, "duplicate recovery JSON key")
        result[key] = value
    return result


def _parse(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data, object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValidationError("init transaction: malformed recovery JSON; preserve the journal") from error
    _require(type(value) is dict, "recovery control must be an object")
    return value


def _dir_identity(value: os.stat_result) -> dict[str, int]:
    _require(stat.S_ISDIR(value.st_mode), "expected a real directory, not a symbolic link or special file")
    _require(not stat.S_IMODE(value.st_mode) & 0o7000, "special directory permission bits are unsupported")
    return {"device": value.st_dev, "inode": value.st_ino, "mode": stat.S_IMODE(value.st_mode)}


def _stat(fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _raw_identity(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _list(fd: int) -> list[str]:
    names = os.listdir(fd)
    _require(len(names) <= MAX_DIRECTORY_ENTRIES, "directory entry bound exceeded")
    return names


def _alias(fd: int, name: str) -> None:
    _require(not any(item != name and _key(item) == _key(name) for item in _list(fd)),
             "existing path has a case/Unicode alias")


@contextmanager
def _descriptor(name: str, flags: int, mode: int = 0o600, *, dir_fd: int,
                owner: InitWorkspace | None = None) -> Iterator[int]:
    if owner is not None and owner._guard is not None:
        with owner._descriptor(name, flags, mode, dir_fd=dir_fd) as handle:
            yield handle
        return
    handle = os.open(name, flags, mode, dir_fd=dir_fd)
    try:
        yield handle
    finally:
        os.close(handle)


def _read(fd: int, name: str, limit: int = MAX_FILE_BYTES, *,
          owner: InitWorkspace | None = None) -> tuple[dict[str, Any], bytes] | None:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    opened = False
    try:
        with _descriptor(name, flags, dir_fd=fd, owner=owner) as handle:
            opened = True
            return _read_owned(handle, fd, name, limit, owner)
    except FileNotFoundError:
        if opened or owner is not None and owner._guard is not None and owner._guard.lifetime_ledger.fatal:
            raise
        return None


def _read_owned(handle: int, fd: int, name: str, limit: int,
                owner: InitWorkspace | None) -> tuple[dict[str, Any], bytes]:
    # The descriptor's prearmed scope is outside this function; an exception in
    # a terminal name/root check is not mistaken for absence at open.
    if owner is not None:
        owner._checkpoint()
    before = os.fstat(handle)
    _require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
             "input must be a bounded regular file, not a symbolic link or special file")
    _require(not stat.S_IMODE(before.st_mode) & 0o7000, "special file permission bits are unsupported")
    if owner is not None and owner._guard is not None:
        _require(before.st_nlink == 1, "desktop edit inputs must have one link")
        named = _stat(fd, name)
        owner._expect_unchanged(named is not None and _raw_identity(named) == _raw_identity(before)
                                and named.st_nlink == 1, "input name changed during acquisition")
    chunks, size = [], 0
    while True:
        if owner is not None:
            owner._checkpoint()
        data = os.read(handle, min(1024**2, limit + 1 - size))
        if owner is not None:
            owner._checkpoint()
        if not data:
            break
        chunks.append(data)
        size += len(data)
        _require(size <= limit, "input exceeded its byte bound")
    unchanged = size == before.st_size and _raw_identity(before) == _raw_identity(os.fstat(handle))
    (owner._expect_unchanged if owner is not None else _require)(unchanged, "input changed during its bounded read")
    if owner is not None and owner._guard is not None:
        from .build_inputs import _file
        named = _stat(fd, name)
        owner._expect_unchanged(named is not None and stat.S_ISREG(named.st_mode)
                                and _file(named) == _file(before)
                                and _file(os.fstat(handle)) == _file(before), "input name changed during its read")
        owner._root_check()
        owner._last_read_facts = tuple(sorted(_file(before).items()))
    data = b"".join(chunks)
    binding = {"device": before.st_dev, "inode": before.st_ino,
               "mode": stat.S_IMODE(before.st_mode), "size": size,
               "sha256": hashlib.sha256(data).hexdigest()}
    # A fully checked terminal read is a fact even if its subsequent descriptor
    # close loses its return. Never erase the decision merely because _move or
    # _install did not return to its caller.
    if owner is not None and owner._terminal_read == (fd, name, binding):
        owner._terminal_seen = name
        owner._terminal_ambiguous = False
    return binding, data


def _binding(fd: int, name: str, *, directory: bool = False, limit: int = MAX_FILE_BYTES,
             owner: InitWorkspace | None = None) -> dict[str, Any] | None:
    if directory:
        value = _stat(fd, name)
        return _dir_identity(value) if value else None
    value = _read(fd, name, limit, owner=owner)
    return value[0] if value else None


def _fsync(fd: int) -> None:
    os.fsync(fd)


def _write(fd: int, name: str, data: bytes, mode: int = 0o600, *, preserve_mode: bool = False,
           owner: InitWorkspace | None = None) -> None:
    _require(len(data) <= MAX_FILE_BYTES, "staged file exceeds its byte bound")
    with _descriptor(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     mode, dir_fd=fd, owner=owner) as handle:
        view = memoryview(data)
        while view:
            if owner is not None:
                owner._checkpoint()
            size = os.write(handle, view[:1024**2])
            _require(size > 0, "staged write made no progress")
            view = view[size:]
        if preserve_mode:
            os.fchmod(handle, mode)
        if owner is not None:
            owner._checkpoint()
        _fsync(handle)
        if owner is not None:
            owner._checkpoint()


def _rename_function() -> Any:
    # Never import POSIX-only modules or bind native symbols during CLI import.
    import ctypes

    _require(sys.platform == "darwin" or sys.platform.startswith("linux"),
             "apply/recover requires a supported local Linux or macOS filesystem")
    library = ctypes.CDLL(None, use_errno=True)
    name = "renameatx_np" if sys.platform == "darwin" else "renameat2"
    _require(hasattr(library, name), "atomic exclusive rename is unavailable; no unsafe fallback is allowed")
    function = getattr(library, name)
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int

    def rename(source_fd: int, source: str, destination_fd: int, destination: str) -> None:
        result = function(source_fd, os.fsencode(source), destination_fd, os.fsencode(destination),
                          4 if sys.platform == "darwin" else 1)
        if result:
            code = ctypes.get_errno()
            raise OSError(code, "exclusive transaction rename failed")

    return rename


@dataclass(frozen=True)
class ObservedFile:
    path: str
    before: dict[str, Any] | None
    data: bytes | None


class InitWorkspace:
    def __init__(self, root: Path):
        self.root = root
        self.fd = -1
        self.parents: dict[str, dict[str, Any] | None] = {}
        self.root_identity: dict[str, int] = {}
        self.private_identity: dict[str, int] | None = None
        self._private_facts: tuple[tuple[str, int], ...] | None = None
        self.observed_bytes = 0
        self._guard: Any = None
        self._scope: Any = None
        self._slots: list[Any] = []
        self._cleanup_mode = False
        self._handoff_depth = 0
        self._raw_observations: dict[str, tuple[tuple[str, int], ...] | None] = {}
        self._parent_facts: dict[str, tuple[tuple[str, int], ...] | None] = {}
        self._last_read_facts: tuple[tuple[str, int], ...] | None = None
        self._captured: dict[str, ObservedFile] = {}
        self._typed_claimed = False
        self._typed_profile: TypedEditProfile | None = None
        self._metadata_targets: Any = None
        self._rooted_revision: Any = None
        # Strong typed domains have original, in-memory authority. The legacy
        # workflow-prefixed storage/method names are shared only by the two
        # explicit original-control profiles, not by persisted CLI recovery.
        # A syntactically
        # valid on-disk journal cannot supply another roster or cleanup target.
        # Incomplete PREPARING is deliberately retained, not name-adopted.
        self._workflow_header: bytes | None = None
        self._workflow_plan: bytes | None = None
        self._workflow_controls: dict[str, dict[str, Any]] = {}
        self._workflow_complete = False
        self._creation = {"state": "NEW"}
        self._install_started = False
        self._installing = False
        self._terminal_seen: str | None = None
        self._terminal_ambiguous = False
        self._terminal_read: tuple[int, str, dict[str, Any]] | None = None
        self._terminal_durable = False
        self._publishing_terminal: str | None = None
        self._journal_clean = False
        self._primary: BaseException | None = None
        self._reason = "none"
        self._unchanged = False
        self._recovery_claimed = False
        self._outcome = InitApplyOutcome("not_started", "not_created", "settled", "none")

    @classmethod
    def borrowed(cls, scope: Any) -> InitWorkspace:
        # Native-only import: discovery/passive imports only need constants.
        from .init_workspace_custody import LockedInitScope
        _require(type(scope) is LockedInitScope, "a concrete original lock scope is required")
        scope.check()
        workspace = cls(scope.lease.root)
        scope.claim_workspace(workspace)
        workspace._guard, workspace._scope = scope.lease.guard, scope
        workspace._typed_profile = scope.lease.profile
        workspace._metadata_targets = scope.lease._metadata_targets
        workspace.fd = scope.fd
        workspace.flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        workspace.root_identity = _dir_identity(os.fstat(workspace.fd))
        return workspace

    @property
    def _state_names(self) -> tuple[str, str, str]:
        if self._typed_profile is TypedEditProfile.METADATA_TEXT:
            return METADATA_STATE_NAMES
        return STATE_NAMES

    @property
    def _original_controls_required(self) -> bool:
        return self._typed_profile in (TypedEditProfile.GITHUB_WORKFLOWS, TypedEditProfile.METADATA_TEXT)

    def _expect_unchanged(self, condition: bool, message: str) -> None:
        """Only an actual comparison mismatch is a metadata stale conflict.

        Do not catch/relabel generic ValidationError or IO failures. Legacy
        domains retain their exact existing comparison exception behavior.
        """
        if not condition and self._typed_profile is TypedEditProfile.METADATA_TEXT:
            raise InitConflict("metadata text: " + message)
        _require(condition, message)

    def _original_target_check(self, item: ObservedFile, message: str) -> None:
        """Consume original target facts before no-op or its initial move.

        This is never used to compare original ctime to writer-owned backups,
        installed replacements or restored objects after a rename.
        """
        self._last_read_facts = None
        self._expect_unchanged(self._current(item.path) == item.before, message)
        if self._typed_profile is TypedEditProfile.METADATA_TEXT:
            _require(self._rooted_revision is not None, "original metadata revision is required")
            original = dict(self._rooted_revision._raw)
            _require(item.path in original, "original metadata raw observation is required")
            self._expect_unchanged(self._last_read_facts == original[item.path],
                                   "original metadata target facts changed")

    def _metadata_dependencies_check(self) -> None:
        """Recheck original read-only bytes/facts, never reparse or retarget.

        Keep dependencies out of the staged/writable roster. Their original
        parent identities still constrain every effect and original recovery.
        """
        if self._typed_profile is not TypedEditProfile.METADATA_TEXT:
            return
        from .init_workspace_custody import MetadataTargets
        from .metadata_text import DEPENDENCY_LIMITS
        targets = self._metadata_targets
        _require(type(targets) is MetadataTargets, "original metadata targets are required")
        targets._check_workspace(self)
        original_raw = dict(targets._raw)
        for (path, before, raw), limit in zip(targets._dependencies, DEPENDENCY_LIMITS):
            self._last_read_facts = None
            with self._parent(path) as parent:
                current = self._read(parent, path.split("/")[-1], limit) if parent is not None else None
                facts = self._last_read_facts
            self._expect_unchanged(current is not None and current[0] == dict(before) and current[1] == raw
                                   and facts == original_raw[path], "original metadata dependency changed")
        for path, facts in targets._parent_facts:
            self._expect_unchanged(self._parent_facts.get(path) == facts,
                                   "original metadata dependency parent facts changed")

    def _dependency_only_parents(self) -> dict[str, dict[str, Any] | None]:
        if self._typed_profile is not TypedEditProfile.METADATA_TEXT:
            return {}
        from .init_workspace_custody import MetadataTargets
        targets = self._metadata_targets
        _require(type(targets) is MetadataTargets, "original metadata targets are required")
        targets._check_workspace(self)
        return targets.dependency_only_parents

    def _checkpoint(self) -> None:
        if self._guard is None:
            return
        self._guard._check_owner()
        if self._cleanup_mode or self._handoff_depth:
            self._guard._poll_edit_stop()
            _require(not self._guard.lifetime_ledger.fatal,
                     "original resource ownership is uncertain; preserve the journal")
        else:
            self._guard.check()

    @contextmanager
    def _handoff(self) -> Iterator[None]:
        guard = self._guard
        self._handoff_depth += 1
        try:
            with (guard.deferred(check_on_exit=False) if guard is not None else nullcontext()):
                yield
        finally:
            self._handoff_depth -= 1

    @contextmanager
    def _descriptor(self, name: str, flags: int, mode: int = 0o600, *, dir_fd: int) -> Iterator[int]:
        self._checkpoint()
        if self._guard is None:
            with _descriptor(name, flags, mode, dir_fd=dir_fd) as handle:
                yield handle
            return
        from .build_inputs import _FD, _fd_cleanup
        slot = _FD(self._guard)
        self._slots.append(slot)  # Prearm before os.open/result publication.
        with _fd_cleanup(slot):
            yield slot.open(name, flags, mode, dir_fd=dir_fd)

    def settle_slots(self) -> None:
        if self._guard is not None:
            from .build_inputs import _attempt_all
            _attempt_all(self._guard, [slot.close for slot in reversed(self._slots)])

    def _read(self, fd: int, name: str, limit: int = MAX_FILE_BYTES):
        return _read(fd, name, limit, owner=self)

    def _binding(self, fd: int, name: str, *, directory: bool = False, limit: int = MAX_FILE_BYTES):
        self._checkpoint()
        return _binding(fd, name, directory=directory, limit=limit, owner=self)

    def _write(self, fd: int, name: str, data: bytes, mode: int = 0o600, *, preserve_mode: bool = False):
        self._checkpoint()
        return _write(fd, name, data, mode, preserve_mode=preserve_mode, owner=self)

    def _fsync(self, fd: int) -> None:
        self._checkpoint()
        _fsync(fd)
        self._checkpoint()

    def _mkdir(self, name: str, mode: int, *, dir_fd: int) -> None:
        self._checkpoint()
        if self._guard is None:
            os.mkdir(name, mode, dir_fd=dir_fd)
            return
        from .build_inputs import _mkdir_private, _directory
        record = self._creation if dir_fd == self.fd and name == self._state_names[0] else {"state": "NEW"}
        # Default interruption cannot fall between the original mkdir receipt
        # and its original identity publication. Ambiguous acquisition is never
        # followed by a pathname-based recovery/adoption attempt.
        with self._handoff():
            try:
                _mkdir_private(name, dir_fd, self._guard, record)
                with self._descriptor(name, self.flags, dir_fd=dir_fd) as child:
                    if mode != 0o700:
                        os.fchmod(child, mode)
                    value = os.fstat(child)
                    identity = _dir_identity(value)
                    _require(identity == self._binding(dir_fd, name, directory=True),
                             "created directory handoff changed")
                    if record is self._creation:
                        self.private_identity = identity
                        self._private_facts = tuple(sorted(_directory(value).items()))
            except BaseException as error:
                if record["state"] == "CREATED":
                    # A missing identity/return is not deletion authority.
                    self._guard._abort(error)
                raise
        self._checkpoint()

    def _unlink(self, name: str, *, dir_fd: int, directory: bool = False) -> None:
        self._checkpoint()
        with self._handoff():
            (os.rmdir if directory else os.unlink)(name, dir_fd=dir_fd)
        self._checkpoint()

    def _control_rename(self, source_fd: int, source: str, destination_fd: int, destination: str) -> None:
        self._checkpoint()
        with self._handoff():
            if self._guard is not None and not self._cleanup_mode:
                self._guard.check()
            self.rename(source_fd, source, destination_fd, destination)
        self._checkpoint()

    def _list(self, fd: int) -> list[str]:
        self._checkpoint()
        names = _list(fd)
        self._checkpoint()
        return names

    def _alias(self, fd: int, name: str) -> None:
        for index, item in enumerate(self._list(fd)):
            if index % 256 == 0:
                self._checkpoint()
            self._expect_unchanged(item == name or _key(item) != _key(name), "existing path has a case/Unicode alias")

    def __enter__(self) -> InitWorkspace:
        _require(self._scope is None, "a borrowed workspace cannot acquire another root or lock")
        _require(sys.platform == "darwin" or sys.platform.startswith("linux"),
                 "apply/recover requires Linux/macOS local filesystem semantics")
        import fcntl

        self.rename = _rename_function()
        self.flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        self.fd = os.open(self.root, self.flags)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.root_identity = _dir_identity(os.fstat(self.fd))
            self._root_check()
        except BaseException as error:
            handle, self.fd = self.fd, -1
            os.close(handle)
            if isinstance(error, BlockingIOError):
                raise ValidationError("init transaction: another init/recovery owns this project; wait for it to finish") from error
            raise
        return self

    def __exit__(self, *_args: Any) -> None:
        if self._scope is not None:
            self.settle_slots()  # Never close a borrowed root/lock description.
            return
        if self.fd >= 0:
            handle, self.fd = self.fd, -1
            os.close(handle)

    def _root_check(self) -> None:
        self._checkpoint()
        if self._scope is not None:
            self._scope.check()
            _require(self.fd == self._scope.fd, "borrowed root descriptor changed")
            return
        _require(_dir_identity(os.stat(self.root, follow_symlinks=False)) == self.root_identity,
                 "project root changed; preserve transaction state")

    def state(self) -> str | None:
        self._root_check()
        for name in ALL_STATE_NAMES:
            self._alias(self.fd, name)
        found = [name for name in ALL_STATE_NAMES if _stat(self.fd, name) is not None]
        self._expect_unchanged(all(name in self._state_names for name in found),
                               "foreign typed transaction state must be preserved by its original owner")
        self._expect_unchanged(len(found) <= 1, "inconsistent simultaneous transaction directories; preserve them")
        return found[0] if found else None

    def require_clean(self) -> None:
        _require(self.state() is None,
                 "pending transaction; run mobile-release init --root <project> --recover before applying again")

    @contextmanager
    def _private(self, name: str) -> Iterator[int]:
        self._root_check()
        _require(name in self._state_names and self.state() == name,
                 "private state is not the admitted original transaction domain")
        with self._descriptor(name, self.flags, dir_fd=self.fd) as handle:
            value = os.fstat(handle)
            _require(value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o700
                     and value.st_dev == self.root_identity["device"],
                     "journal must be a private, owned, same-filesystem directory")
            self._private_check(handle, name)
            yield handle

    def _private_check(self, fd: int, name: str) -> None:
        try:
            self._root_check()
            _require(name in self._state_names and self.state() == name,
                     "private state domain changed")
            self._alias(self.fd, name)
            value = os.fstat(fd)
            identity = _dir_identity(value)
            _require(value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o700
                     and identity == self._binding(self.fd, name, directory=True)
                     and (self.private_identity is None or identity == self.private_identity),
                     "private transaction namespace changed")
            if self._guard is not None:
                from .build_inputs import _directory
                _require(self._private_facts is not None
                         and tuple(sorted(_directory(value).items())) == self._private_facts,
                         "original private directory facts changed")
        except (OSError, ValidationError) as error:
            raise InitConflict("init transaction: private namespace changed or cannot be verified; preserve all captured objects") from error
        self.private_identity = identity

    @contextmanager
    def _parent(self, path: str, *, planning: bool = False) -> Iterator[int | None]:
        self._root_check()
        handle, current, missing = self.fd, [], False
        with ExitStack() as opened:
            for part in path.split("/")[:-1]:
                self._checkpoint()
                current.append(part)
                relative = "/".join(current)
                if not missing:
                    self._alias(handle, part)
                    value = _stat(handle, part)
                    if relative in self.parents:
                        self._expect_unchanged(value is None or stat.S_ISDIR(value.st_mode),
                                               "observed destination ancestor type changed")
                    identity = _dir_identity(value) if value else None
                    if identity:
                        _require(identity["device"] == self.root_identity["device"]
                                 and (self._scope is not None or not os.path.ismount(self.root / relative)),
                                 "nested mount or different filesystem is unsupported")
                    if planning and relative not in self.parents:
                        self.parents[relative] = identity
                    if self._guard is not None:
                        from .build_inputs import _directory
                        facts = tuple(sorted(_directory(value).items())) if value is not None else None
                        if self._typed_profile is TypedEditProfile.METADATA_TEXT and self._rooted_revision is not None:
                            original = dict(self._rooted_revision._parent_facts).get(relative)
                            if original is not None:
                                self._expect_unchanged(facts == original, "original metadata ancestor facts changed")
                        self._parent_facts[relative] = facts
                    _require(relative in self.parents, "destination ancestor is outside the original inventory")
                    self._expect_unchanged(identity == self.parents[relative],
                                           "destination ancestor changed or is unsafe")
                    if value is None:
                        missing = True
                    else:
                        child = opened.enter_context(self._descriptor(part, self.flags, dir_fd=handle))
                        self._expect_unchanged(_dir_identity(os.fstat(child)) == identity, "ancestor changed while opening")
                        if self._guard is not None:
                            self._expect_unchanged(tuple(sorted(_directory(os.fstat(child)).items())) == self._parent_facts[relative],
                                                   "original ancestor metadata changed while opening")
                        handle = child
                elif planning:
                    # Recheck preloads parents from the original revision.
                    # The descendant of an absent ancestor is still an explicit
                    # absence fact; skipping its existing key loses that fact.
                    if relative not in self.parents:
                        self.parents[relative] = None
                    self._expect_unchanged(self.parents[relative] is None,
                                           "destination ancestor changed or is unsafe")
                    if self._guard is not None:
                        self._parent_facts[relative] = None
            if not missing:
                self._alias(handle, path.split("/")[-1])
            yield None if missing else handle

    def observe(self, path: str, *, limit: int = MAX_FILE_BYTES) -> ObservedFile:
        self._checkpoint()
        validate_paths([path])
        self._last_read_facts = None
        with self._parent(path, planning=True) as parent:
            value = self._read(parent, path.split("/")[-1], min(limit, MAX_TOTAL_BYTES - self.observed_bytes)) if parent is not None else None
            facts = self._last_read_facts if value is not None else None
        self.observed_bytes += value[0]["size"] if value else 0
        if self._guard is not None:
            self._raw_observations[path] = facts
        self._checkpoint()
        result = ObservedFile(path, value[0] if value else None, value[1] if value else None)
        self._captured[path] = result
        return result

    def _current(self, path: str, *, directory: bool = False) -> dict[str, Any] | None:
        with self._parent(path) as parent:
            if directory and self._typed_profile is TypedEditProfile.METADATA_TEXT and self._rooted_revision is not None:
                from .build_inputs import _directory
                expected = dict(self._rooted_revision._parent_facts).get(path)
                if expected is not None:
                    current = _stat(parent, path.split("/")[-1]) if parent is not None else None
                    self._expect_unchanged(current is not None and stat.S_ISDIR(current.st_mode)
                                           and tuple(sorted(_directory(current).items())) == expected,
                                           "original metadata target parent facts changed")
            return self._binding(parent, path.split("/")[-1], directory=directory) if parent is not None else None

    def _namespace_check(self, *, changing: str | None = None) -> None:
        self._root_check()
        self._metadata_dependencies_check()
        for path, expected in self.parents.items():
            if changing is not None and (path == changing or path.startswith(changing + "/")):
                continue
            self._expect_unchanged(self._current(path, directory=True) == expected, "destination namespace changed")

    def _move(self, source_fd: int, source: str, destination_fd: int, destination: str,
              expected: dict[str, Any], *, directory: bool = False, directory_path: str | None = None) -> None:
        self._checkpoint()
        with self._handoff():
            self._move_owned(source_fd, source, destination_fd, destination, expected,
                             directory=directory, directory_path=directory_path)
        self._checkpoint()

    def _move_owned(self, source_fd: int, source: str, destination_fd: int, destination: str,
                    expected: dict[str, Any], *, directory: bool,
                    directory_path: str | None) -> None:
        self._namespace_check()
        self._expect_unchanged(self._binding(source_fd, source, directory=directory) == expected, "move source changed")
        self._expect_unchanged(_stat(destination_fd, destination) is None, "exclusive move destination appeared")
        failure: BaseException | None = None
        try:
            if self._guard is not None and not self._cleanup_mode:
                self._guard.check()  # Last stop check before the next effect.
            if self._installing:
                self._install_started = True
            if self._publishing_terminal is not None:
                self._terminal_ambiguous = True
            self.rename(source_fd, source, destination_fd, destination)
        except BaseException as error:
            failure = error
        captured = _stat(destination_fd, destination)
        if captured is not None and _stat(source_fd, source) is None:
            try:
                if self._publishing_terminal is not None:
                    self._terminal_read = (destination_fd, destination, expected)
                try:
                    self._expect_unchanged(self._binding(destination_fd, destination, directory=directory) == expected,
                                           "move captured a changed source")
                finally:
                    self._terminal_read = None
                if directory:
                    with self._descriptor(destination, self.flags, dir_fd=destination_fd) as handle:
                        self._expect_unchanged(not self._list(handle), "moved directory gained unrelated contents")
                if self._publishing_terminal is not None:
                    self._terminal_seen = self._publishing_terminal
            except BaseException as error:
                if self._publishing_terminal is not None:
                    # A genuine terminal decision is irreversible. Incomplete
                    # proof is uncertainty, not authority to move it back.
                    raise
                # Restore the captured object, not an assumed precheck inode.
                # If either location changed again, preserve both as a conflict.
                self._namespace_check(changing=directory_path)
                if _stat(source_fd, source) is None and _raw_identity(captured) == _raw_identity(
                    os.stat(destination, dir_fd=destination_fd, follow_symlinks=False)
                ):
                    self.rename(destination_fd, destination, source_fd, source)
                    self._fsync(source_fd)
                    self._fsync(destination_fd)
                if self._typed_profile is TypedEditProfile.METADATA_TEXT and isinstance(error, InitConflict):
                    raise
                raise ValidationError("init transaction: source changed during move; captured user object preserved, reconcile before recovery") from error
        if failure is not None:
            raise failure
        self._expect_unchanged(captured is not None and self._binding(destination_fd, destination, directory=directory) == expected,
                               "exclusive move did not produce its exact expected object")
        self._namespace_check(changing=directory_path)
        self._fsync(source_fd)
        self._fsync(destination_fd)

    def _state_move(self, old: str, new: str) -> None:
        self._checkpoint()
        with self._handoff():
            self._state_move_owned(old, new)
        self._checkpoint()

    def _state_move_owned(self, old: str, new: str) -> None:
        self._root_check()
        _require(old in self._state_names and new in self._state_names, "state handoff cannot cross transaction domains")
        self._expect_unchanged(self.state() == old, "original transaction state changed before handoff")
        self._metadata_dependencies_check()
        expected = self._binding(self.fd, old, directory=True)
        self._expect_unchanged(expected is not None, "transaction directory disappeared")
        self._expect_unchanged(self.private_identity is None or expected == self.private_identity,
                               "transaction directory changed before handoff")
        failure: BaseException | None = None
        try:
            if self._guard is not None and not self._cleanup_mode:
                self._guard.check()
            self.rename(self.fd, old, self.fd, new)
        except BaseException as error:
            failure = error
        captured = _stat(self.fd, new)
        if captured is not None and _stat(self.fd, old) is None and (
            not stat.S_ISDIR(captured.st_mode)
            or (captured.st_dev, captured.st_ino, stat.S_IMODE(captured.st_mode))
            != (expected["device"], expected["inode"], expected["mode"])
        ):
            self._root_check()
            _require(_raw_identity(captured) == _raw_identity(os.stat(new, dir_fd=self.fd, follow_symlinks=False)),
                     "captured transaction object changed; preserve both namespaces")
            self.rename(self.fd, new, self.fd, old)
            self._fsync(self.fd)
            self._expect_unchanged(False, "journal namespace changed; captured object restored")
        if failure is not None:
            raise failure
        self._expect_unchanged(self._binding(self.fd, new, directory=True) == expected, "transaction directory changed during handoff")
        self._fsync(self.fd)

    def _header(self, fd: int) -> dict[str, Any]:
        item = self._read(fd, "header.json", MAX_CONTROL_BYTES)
        _require(item is not None, "missing recovery header")
        if self._original_controls_required:
            self._workflow_control("header.json", item[0])
            self._expect_unchanged(item[1] == self._workflow_header, "original workflow header changed")
        header = _parse(item[1])
        header_keys = {"schemaVersion", "transactionId", "root"}
        if self._typed_profile is TypedEditProfile.METADATA_TEXT:
            header_keys.add("domain")
            _require(header.get("domain") == "metadata_text", "metadata journal domain differs")
        _require(set(header) == header_keys
                 and type(header["schemaVersion"]) is int and header["schemaVersion"] == 1
                 and isinstance(header["transactionId"], str)
                 and re.fullmatch(r"[0-9a-f]{32}", header["transactionId"]) is not None
                 and self._valid_identity(header["root"], directory=True)
                 and header["root"] == self.root_identity, "invalid recovery header/root binding")
        return header

    @staticmethod
    def _valid_identity(value: Any, *, directory: bool = False) -> bool:
        keys = {"device", "inode", "mode"} | (set() if directory else {"size", "sha256"})
        return (type(value) is dict and set(value) == keys
                and all(type(value[k]) is int and 0 <= value[k] < 2**64 for k in keys - {"sha256"})
                and value["inode"] > 0 and value["mode"] <= 0o777
                and (directory or (value["size"] <= MAX_FILE_BYTES and isinstance(value["sha256"], str)
                                    and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None)))

    def _load(self, fd: int) -> dict[str, Any]:
        header = self._header(fd)
        item = self._read(fd, "plan.json", MAX_CONTROL_BYTES)
        _require(item is not None, "missing READY plan; preserve journal, do not guess")
        if self._original_controls_required:
            self._workflow_control("plan.json", item[0])
            self._expect_unchanged(item[1] == self._workflow_plan, "original workflow plan changed")
        plan = _parse(item[1])
        _require(set(plan) == {*header, "directories", "files"}
                 and _json({k: plan[k] for k in header}) == _json(header), "plan/header binding differs")
        _require(type(plan["files"]) is list and type(plan["directories"]) is list
                 and 0 < len(plan["files"]) <= MAX_FILES and len(plan["directories"]) <= MAX_FILES,
                 "invalid recovery inventory")
        for entry in plan["files"]:
            _require(type(entry) is dict and set(entry) == {"path", "before", "after"}
                     and type(entry["path"]) is str, "invalid recovery file entry")
            _require((entry["before"] is not None or entry["after"] is not None)
                     and all(v is None or self._valid_identity(v) for v in (entry["before"], entry["after"])),
                     "invalid recovery file identity")
        validate_paths([entry["path"] for entry in plan["files"]])
        expected_dirs = {"/".join(e["path"].split("/")[:i]) for e in plan["files"]
                         for i in range(1, len(e["path"].split("/")))}
        seen = set()
        for entry in plan["directories"]:
            _require(type(entry) is dict and set(entry) == {"path", "before", "after"}
                     and type(entry["path"]) is str and entry["path"] not in seen,
                     "invalid recovery directory entry")
            seen.add(entry["path"])
            _require((entry["before"] is None) != (entry["after"] is None)
                     and self._valid_identity(entry["before"] or entry["after"], directory=True),
                     "invalid directory identity")
        _require(seen == expected_dirs, "recovery directory inventory differs from file ancestors")
        _require([e["path"] for e in plan["directories"]] == sorted(expected_dirs, key=lambda p: (p.count("/"), p)),
                 "recovery directory order is invalid")
        _require(all(v["device"] == self.root_identity["device"] for section in ("directories", "files")
                     for e in plan[section] for v in (e["before"], e["after"]) if v is not None),
                 "recovery inode belongs to another filesystem")
        _require(sum(v["size"] for e in plan["files"] for v in (e["before"], e["after"]) if v) <= MAX_TOTAL_BYTES,
                 "recovery byte bound exceeded")
        if self._typed_profile is TypedEditProfile.GITHUB_WORKFLOWS:
            _require(tuple(e["path"] for e in plan["files"]) == self._typed_profile.paths
                     and tuple(e["path"] for e in plan["directories"]) == self._typed_profile.directories
                     and all((e["before"] is None) != (e["after"] is None) for e in plan["files"]),
                     "workflow recovery cannot replace or adopt another inventory")
        elif self._typed_profile is TypedEditProfile.METADATA_TEXT:
            from .init_workspace_custody import MetadataTargets
            from .metadata_text import MAX_TEXT_BYTES
            targets = self._metadata_targets
            _require(type(targets) is MetadataTargets, "metadata journal lacks original targets")
            targets._check_workspace(self)
            _require(tuple(e["path"] for e in plan["files"]) == targets.paths
                     and tuple(e["path"] for e in plan["directories"]) == targets.directories
                     and all(e["before"] == self._captured[e["path"]].before
                             and all(v is None or v["size"] <= MAX_TEXT_BYTES for v in (e["before"], e["after"]))
                             for e in plan["files"]),
                     "metadata recovery cannot adopt another target or dependency inventory")
        self.parents = {**self._dependency_only_parents(),
                        **{e["path"]: e["before"] or e["after"] for e in plan["directories"]}}
        return plan

    def _workflow_control(self, name: str, identity: Any) -> dict[str, Any]:
        """Return only original control authority, including renamed markers."""
        original = {"COMMITTED": "commit.pending", "ROLLED_BACK": "rollback.pending"}.get(name, name)
        expected = self._workflow_controls.get(original)
        self._expect_unchanged(expected is not None and identity == expected,
                               "original workflow control identity changed")
        return expected

    def _bind_workflow_controls(self, fd: int, header: bytes, plan: bytes,
                                parsed_plan: dict[str, Any]) -> None:
        """Freeze completed original staging before any READY publication.

        Before this completes, automatic recovery retains PREPARING. These
        bytes come from the original renderer-independent generated plan, not
        from a recovery parser or a subsequently supplied digest.
        """
        _require(not self._workflow_controls and self._workflow_header is None
                 and self._workflow_plan is None, "workflow controls are one-use")
        expected = {"header.json": header, "plan.json": plan,
                    "commit.pending": self._marker(parsed_plan, "COMMITTED"),
                    "rollback.pending": self._marker(parsed_plan, "ROLLED_BACK")}
        captured = {}
        for name, content in expected.items():
            item = self._read(fd, name, MAX_CONTROL_BYTES)
            self._expect_unchanged(item is not None and item[1] == content,
                                   "workflow staging control differs from original bytes")
            captured[name] = dict(item[0])
        self._workflow_header, self._workflow_plan = header, plan
        self._workflow_controls = captured

    @staticmethod
    def _marker(plan: dict[str, Any], state: str) -> bytes:
        return _json({"schemaVersion": 1, "transactionId": plan["transactionId"],
                      "planSha256": hashlib.sha256(_json(plan)).hexdigest(), "state": state})

    def _terminal(self, fd: int, plan: dict[str, Any]) -> str | None:
        present = []
        for state, pending in (("COMMITTED", "commit.pending"), ("ROLLED_BACK", "rollback.pending")):
            item, staged = self._read(fd, state, MAX_CONTROL_BYTES), self._read(fd, pending, MAX_CONTROL_BYTES)
            _require((item is None) != (staged is None), "missing or duplicated terminal-marker location")
            if self._original_controls_required:
                self._workflow_control(state if item is not None else pending, (item or staged)[0])
            _require((item or staged)[1] == self._marker(plan, state), "terminal marker binding differs")
            if item:
                present.append(state)
        _require(len(present) <= 1, "contradictory terminal states")
        return present[0] if present else None

    def _publish_terminal(self, fd: int, plan: dict[str, Any], state: str) -> None:
        self._checkpoint()
        _require(self._terminal(fd, plan) is None, "transaction is already terminal")
        pending = "commit.pending" if state == "COMMITTED" else "rollback.pending"
        identity = self._binding(fd, pending)
        if self._original_controls_required:
            identity = self._workflow_control(pending, identity)
        assert identity is not None
        # This is a native handoff, not a whole-session cancellation deferral.
        # The decision latches inside its verified read, before fsync/close.
        with self._handoff():
            self._publishing_terminal = state
            try:
                self._move(fd, pending, fd, state, identity)
                self._terminal_durable = True
            finally:
                self._publishing_terminal = None
        self._checkpoint()

    def _inventory(self, fd: int, plan: dict[str, Any]) -> None:
        allowed = {"header.json", "plan.json", "commit.pending", "rollback.pending", "COMMITTED", "ROLLED_BACK"}
        allowed |= {f"{prefix}-{i}" for i, e in enumerate(plan["files"]) if e["after"]
                    for prefix in ("new", "old") if prefix == "new" or e["before"]}
        allowed |= {f"directory-{i}" for i, e in enumerate(plan["directories"]) if e["after"]}
        self._expect_unchanged(set(self._list(fd)) <= allowed, "unexpected journal contents; preserve them")

    def _locations(self, fd: int, plan: dict[str, Any], *, final: str | None = None) -> None:
        self._inventory(fd, plan)
        self._metadata_dependencies_check()
        # Missing new parents are valid only while their recorded empty inode is staged.
        self.parents = self._dependency_only_parents()
        for i, entry in enumerate(plan["directories"]):
            path, before, after = entry["path"], entry["before"], entry["after"]
            current = self._current(path, directory=True)
            staged = self._binding(fd, f"directory-{i}", directory=True) if after else None
            if before:
                self._expect_unchanged(current == before, "original destination directory changed")
                self.parents[path] = before
            else:
                self._expect_unchanged((current == after and staged is None) or (current is None and staged == after),
                                       "created directory has missing, duplicated or changed identity")
                if staged:
                    with self._descriptor(f"directory-{i}", self.flags, dir_fd=fd) as child:
                        self._expect_unchanged(not self._list(child), "staged directory has unexpected contents")
                self._expect_unchanged(final is None or (final == "new" and current == after) or (final == "old" and staged == after),
                                       "directory set does not match final state")
                self.parents[path] = current
        for i, entry in enumerate(plan["files"]):
            current = self._current(entry["path"])
            before, after = entry["before"], entry["after"]
            if after is None:
                self._expect_unchanged(current == before, "preserved input changed")
                if self._typed_profile is TypedEditProfile.METADATA_TEXT:
                    self._original_target_check(self._captured[entry["path"]], "preserved metadata input changed")
                continue
            staged, backup = self._binding(fd, f"new-{i}"), self._binding(fd, f"old-{i}")
            old = current == before and staged == after and backup is None
            between = bool(before) and current is None and staged == after and backup == before
            new = current == after and staged is None and backup == before
            self._expect_unchanged(old or between or new, "file state changed or original backup is missing; preserve user edits and journal")
            self._expect_unchanged(final is None or (final == "old" and old) or (final == "new" and new),
                                   "file set does not match final state")
        # Never retire an owned directory containing an unrelated editor's file.
        expected = {e["path"] for section in ("directories", "files") for e in plan[section]}
        for entry in plan["directories"]:
            if entry["after"] and self.parents[entry["path"]] is not None:
                with self._parent(entry["path"] + "/placeholder") as parent:
                    assert parent is not None
                    self._expect_unchanged(all(entry["path"] + "/" + name in expected for name in self._list(parent)),
                                           "created directory contains unrelated user content; preserve it")

    def _prepare(self, changes: list[tuple[ObservedFile, bytes | None]]) -> dict[str, Any]:
        self.require_clean()
        self._metadata_dependencies_check()
        _require(sum(len(payload or b"") + (item.before or {}).get("size", 0)
                     for item, payload in changes) <= MAX_TOTAL_BYTES, "total input/staging byte bound exceeded")
        for item, _ in changes:
            _require(item.before is None or item.before["device"] == self.root_identity["device"],
                     "input belongs to another filesystem")
            self._original_target_check(item, "input changed after planning")
        self._mkdir(self._state_names[0], 0o700, dir_fd=self.fd)
        with self._private(self._state_names[0]) as fd:
            header = {"schemaVersion": 1, "transactionId": uuid.uuid4().hex, "root": self.root_identity}
            if self._typed_profile is TypedEditProfile.METADATA_TEXT:
                header["domain"] = "metadata_text"
            self._write(fd, "header.tmp", _json(header))
            self._control_rename(fd, "header.tmp", fd, "header.json")
            self._fsync(fd)
            self._fsync(self.fd)
            # Exercise actual local filesystem semantics before touching destinations.
            self._mkdir("probe-a", 0o700, dir_fd=fd)
            self._mkdir("probe-b", 0o700, dir_fd=fd)
            try:
                self._control_rename(fd, "probe-a", fd, "probe-b")
            except FileExistsError:
                pass
            else:
                raise ValidationError("init transaction: filesystem did not enforce exclusive rename")
            self._control_rename(fd, "probe-a", fd, "probe-c")
            self._unlink("probe-c", dir_fd=fd, directory=True)
            self._unlink("probe-b", dir_fd=fd, directory=True)
            directories = []
            target_parents = (self._metadata_targets.directories if self._typed_profile is TypedEditProfile.METADATA_TEXT
                              else tuple(sorted(self.parents, key=lambda p: (p.count("/"), p))))
            for i, path in enumerate(target_parents):
                before, after = self.parents[path], None
                if before is None:
                    self._mkdir(f"directory-{i}", 0o755, dir_fd=fd)
                    after = self._binding(fd, f"directory-{i}", directory=True)
                directories.append({"path": path, "before": before, "after": after})
            files = []
            for i, (item, payload) in enumerate(changes):
                after = None
                if payload is not None:
                    mode = item.before["mode"] if item.before else 0o644
                    self._write(fd, f"new-{i}", payload, mode, preserve_mode=item.before is not None)
                    after = self._binding(fd, f"new-{i}")
                files.append({"path": item.path, "before": item.before, "after": after})
            plan = {**header, "directories": directories, "files": files}
            _require(len(_json(plan)) <= MAX_CONTROL_BYTES, "recovery plan exceeds its byte bound")
            self._write(fd, "plan.tmp", _json(plan))
            self._control_rename(fd, "plan.tmp", fd, "plan.json")
            self._write(fd, "commit.pending", self._marker(plan, "COMMITTED"))
            self._write(fd, "rollback.pending", self._marker(plan, "ROLLED_BACK"))
            self._fsync(fd)
            for item, _ in changes:
                self._original_target_check(item, "input changed during staging")
            if self._original_controls_required:
                self._bind_workflow_controls(fd, _json(header), _json(plan), plan)
            # Creation and recovery must accept exactly the same contract.
            # Validate serialized bytes/locations before publishing READY.
            self._locations(fd, self._load(fd), final="old")
            _require(self._terminal(fd, plan) is None, "staged transaction cannot already be terminal")
            if self._original_controls_required:
                self._workflow_complete = True
        self._state_move(self._state_names[0], self._state_names[1])
        return plan

    def _install(self, fd: int, plan: dict[str, Any]) -> None:
        self._locations(fd, plan, final="old")
        for i, entry in enumerate(plan["directories"]):
            if entry["after"]:
                with self._parent(entry["path"]) as parent:
                    _require(parent is not None, "new directory parent is missing")
                    self._move(fd, f"directory-{i}", parent, entry["path"].split("/")[-1],
                               entry["after"], directory=True, directory_path=entry["path"])
                self.parents[entry["path"]] = entry["after"]
        for i, entry in enumerate(plan["files"]):
            if entry["after"]:
                with self._parent(entry["path"]) as parent:
                    _require(parent is not None, "file parent is missing")
                    leaf = entry["path"].split("/")[-1]
                    self._expect_unchanged(self._binding(parent, leaf) == entry["before"], "destination changed before installation")
                    if self._typed_profile is TypedEditProfile.METADATA_TEXT:
                        self._original_target_check(self._captured[entry["path"]], "metadata destination changed before installation")
                    if entry["before"]:
                        self._move(parent, leaf, fd, f"old-{i}", entry["before"])
                    self._move(fd, f"new-{i}", parent, leaf, entry["after"])
        self._locations(fd, plan, final="new")
        self._publish_terminal(fd, plan, "COMMITTED")

    def _rollback(self, fd: int, plan: dict[str, Any]) -> None:
        _require(self._terminal_seen != "COMMITTED" and not self._terminal_ambiguous,
                 "an irreversible or uncertain terminal decision cannot be rolled back")
        _require(self._terminal(fd, plan) is None, "a terminal transaction cannot be rolled back")
        self._locations(fd, plan)
        for i, entry in reversed(list(enumerate(plan["files"]))):
            if entry["after"]:
                with self._parent(entry["path"]) as parent:
                    if parent is None:
                        continue
                    leaf = entry["path"].split("/")[-1]
                    current = self._binding(parent, leaf)
                    if current == entry["after"]:
                        self._move(parent, leaf, fd, f"new-{i}", entry["after"])
                    if self._binding(fd, f"old-{i}") is not None:
                        self._move(fd, f"old-{i}", parent, leaf, entry["before"])
        for i, entry in reversed(list(enumerate(plan["directories"]))):
            if entry["after"] and self.parents[entry["path"]] is not None:
                with self._parent(entry["path"]) as parent:
                    assert parent is not None
                    self._move(parent, entry["path"].split("/")[-1], fd, f"directory-{i}",
                               entry["after"], directory=True, directory_path=entry["path"])
                self.parents[entry["path"]] = None
        self._locations(fd, plan, final="old")
        self._publish_terminal(fd, plan, "ROLLED_BACK")

    def _preparing_inventory(self, fd: int) -> None:
        names = set(self._list(fd))
        if self._original_controls_required:
            _require(self._workflow_complete,
                     "incomplete original workflow preparation must be retained")
            plan = self._load(fd)
            expected = set(self._workflow_controls)
            expected.update(f"new-{i}" for i, entry in enumerate(plan["files"]) if entry["after"])
            expected.update(f"directory-{i}" for i, entry in enumerate(plan["directories"]) if entry["after"])
            self._expect_unchanged(names == expected, "original workflow preparation inventory changed")
            self._locations(fd, plan, final="old")
            _require(self._terminal(fd, plan) is None, "workflow preparation is unexpectedly terminal")
            return
        def slot(name: str, prefix: str) -> bool:
            match = re.fullmatch(prefix + r"-(0|[1-9][0-9]{0,2})", name)
            return match is not None and int(match[1]) < MAX_FILES

        if "header.json" not in names:
            _require(names <= {"header.tmp"}, "unrecognized preparation; preserve it for inspection")
        else:
            self._header(fd)
        staged_bytes = 0
        for name in names:
            value = _stat(fd, name)
            assert value is not None
            if slot(name, "directory") or name in PROBES:
                _require(stat.S_ISDIR(value.st_mode), "unsafe preparation directory")
                with self._descriptor(name, self.flags, dir_fd=fd) as child:
                    _require(not self._list(child), "preparation directory has unexpected contents")
            else:
                _require(name in CONTROLS - {"COMMITTED", "ROLLED_BACK"}
                         or slot(name, "new"),
                         "unrecognized preparation content; no original backup is legal here")
                item = self._read(fd, name, MAX_CONTROL_BYTES if name in CONTROLS else MAX_FILE_BYTES)
                if name not in CONTROLS and item is not None:
                    staged_bytes += item[0]["size"]
                    _require(staged_bytes <= MAX_TOTAL_BYTES, "preparation byte bound exceeded")
        _require(len(names) <= 2 * MAX_FILES + len(CONTROLS) + len(PROBES), "preparation inventory bound exceeded")

    def _cleanup(self) -> None:
        self._metadata_dependencies_check()
        with self._private(self._state_names[2]) as fd:
            workflow_entries: dict[str, tuple[bool, dict[str, Any]]] = {}
            if self._original_controls_required:
                _require(self._workflow_complete,
                         "incomplete original workflow preparation must be retained")
                # A single original in-session cleanup starts with complete
                # control proof. Lost/modified control suffixes cannot be
                # adopted by the generic persisted CLI-recovery allowance.
                original = self._load(fd)
                self._inventory(fd, original)
                self._terminal(fd, original)
                # Derive only the original fixed proof, not fresh journal
                # authority. Preserved files have no legal old/new staging slot.
                workflow_entries = {name: (False, value) for name, value in self._workflow_controls.items()}
                workflow_entries.update(COMMITTED=workflow_entries["commit.pending"],
                                        ROLLED_BACK=workflow_entries["rollback.pending"])
                workflow_entries.update({f"new-{i}": (False, entry["after"])
                                         for i, entry in enumerate(original["files"]) if entry["after"]})
                if self._typed_profile is TypedEditProfile.METADATA_TEXT:
                    workflow_entries.update({f"old-{i}": (False, entry["before"])
                                             for i, entry in enumerate(original["files"])
                                             if entry["before"] is not None and entry["after"] is not None})
                workflow_entries.update({f"directory-{i}": (True, entry["after"])
                                         for i, entry in enumerate(original["directories"]) if entry["after"]})
            names = set(self._list(fd))
            _require(len(names) <= 2 * MAX_FILES + len(CONTROLS) + len(PROBES), "cleanup inventory bound exceeded")
            # Capture before validating the phase/content, not afterward: a
            # later read must not adopt an intervening editor's replacement.
            entries: dict[str, tuple[bool, dict[str, Any]]] = {}
            observed_bytes = 0
            for name in names:
                value = _stat(fd, name)
                _require(value is not None, "cleanup entry disappeared")
                directory = stat.S_ISDIR(value.st_mode)
                if directory:
                    binding = _dir_identity(value)
                else:
                    item = self._read(fd, name, MAX_CONTROL_BYTES if name in CONTROLS else MAX_FILE_BYTES)
                    _require(item is not None, "cleanup entry disappeared")
                    binding = item[0]
                    observed_bytes += binding["size"]
                    _require(observed_bytes <= MAX_TOTAL_BYTES + len(CONTROLS) * MAX_CONTROL_BYTES,
                             "cleanup byte bound exceeded")
                entries[name] = (directory, binding)
                if self._original_controls_required:
                    _require(workflow_entries.get(name) == entries[name],
                             "original workflow cleanup entry changed")
                    entries[name] = workflow_entries[name]

            def verify_entry(name: str) -> bool:
                try:
                    self._private_check(fd, self._state_names[2])
                    directory, expected = entries[name]
                    if self._original_controls_required:
                        _require(workflow_entries.get(name) == (directory, expected),
                                 "original workflow cleanup proof changed")
                    _require(self._binding(fd, name, directory=directory,
                                      limit=MAX_CONTROL_BYTES if name in CONTROLS else MAX_FILE_BYTES) == expected,
                             "cleanup entry changed")
                except (OSError, ValidationError) as error:
                    raise InitConflict("init transaction: cleanup entry changed or cannot be verified; preserve private state and user edits") from error
                return directory

            data = names - CONTROLS
            terminal = bool(names & {"COMMITTED", "ROLLED_BACK"})
            plan = None
            if terminal:
                # Cleanup deletes data before control proof, and the terminal
                # marker after the plan. Accept only those exact suffixes.
                if "plan.json" in names:
                    plan = self._load(fd)
                    self._inventory(fd, plan)
                    states = names & {"COMMITTED", "ROLLED_BACK"}
                    _require(len(states) == 1, "contradictory cleanup terminal states")
                    state = next(iter(states))
                    marker = self._read(fd, state, MAX_CONTROL_BYTES)
                    if self._original_controls_required:
                        self._workflow_control(state, marker[0] if marker is not None else None)
                    _require(marker[1] == self._marker(plan, state),
                             "cleanup terminal marker binding differs")
                    for state, pending in (("COMMITTED", "commit.pending"), ("ROLLED_BACK", "rollback.pending")):
                        item = self._read(fd, pending, MAX_CONTROL_BYTES)
                        if self._original_controls_required:
                            _require((item is None) == (state in states),
                                     "original workflow cleanup pending marker disappeared")
                            if item is not None:
                                self._workflow_control(pending, item[0])
                        _require(not (item is not None and state in states), "duplicated cleanup marker")
                        _require(item is None or item[1] == self._marker(plan, state), "cleanup pending marker differs")
                    if data:
                        self._terminal(fd, plan)
                    for i, entry in enumerate(plan["files"]):
                        for prefix, binding in (("new", entry["after"]), ("old", entry["before"])):
                            name = f"{prefix}-{i}"
                            if name in data:
                                _require(binding is not None and self._binding(fd, name) == binding,
                                         "cleanup captured file changed; preserve it")
                    for i, entry in enumerate(plan["directories"]):
                        name = f"directory-{i}"
                        if name in data:
                            _require(entry["after"] is not None and self._binding(fd, name, directory=True) == entry["after"],
                                     "cleanup directory identity changed")
                            with self._descriptor(name, self.flags, dir_fd=fd) as child:
                                _require(not self._list(child), "cleanup directory contains unrelated content")
                else:
                    _require(not data and len(names & {"COMMITTED", "ROLLED_BACK"}) == 1
                             and names <= {"COMMITTED", "ROLLED_BACK", "header.json"},
                             "invalid cleanup control suffix; preserve it")
                    header = self._header(fd)
                    state = next(iter(names & {"COMMITTED", "ROLLED_BACK"}))
                    marker = _parse(self._read(fd, state, MAX_CONTROL_BYTES)[1])
                    _require(set(marker) == {"schemaVersion", "transactionId", "planSha256", "state"}
                             and type(marker["schemaVersion"]) is int and marker["schemaVersion"] == 1
                             and marker["transactionId"] == header["transactionId"] and marker["state"] == state
                             and isinstance(marker["planSha256"], str)
                             and re.fullmatch(r"[0-9a-f]{64}", marker["planSha256"]) is not None,
                             "invalid cleanup terminal marker")
            else:
                self._preparing_inventory(fd)
                if "plan.json" in names:
                    self._load(fd)  # An atomically published plan is never partial.
            # Data first, then control objects. The cleanup pathname remains
            # irreversible even after the final marker/header has been removed.
            for name in sorted(data):
                if verify_entry(name):
                    self._unlink(name, dir_fd=fd, directory=True)  # Empty only; never recursive.
                else:
                    self._unlink(name, dir_fd=fd)
                self._fsync(fd)
            for name in ("header.tmp", "plan.tmp", "commit.pending", "rollback.pending",
                         "plan.json", "COMMITTED", "ROLLED_BACK", "header.json"):
                if name in names:
                    _require(not verify_entry(name), "unsafe cleanup control")
                    self._unlink(name, dir_fd=fd)
                    self._fsync(fd)
            self._private_check(fd, self._state_names[2])
            _require(not self._list(fd), "cleanup directory gained unrelated content")
            self._unlink(self._state_names[2], dir_fd=self.fd, directory=True)
        self._fsync(self.fd)
        self._journal_clean = True

    def current_outcome(self, reason: str = "none") -> InitApplyOutcome:
        """Project facts held by this original workspace, including lost returns.

        No additional IO, observer reopens, or exception-text interpretation is
        performed. The outer scope/lease adds its own close evidence.
        """
        if self._reason == "none" and reason != "none":
            self._reason = reason
        if self._terminal_seen == "COMMITTED":
            effect = "committed"
        elif self._terminal_ambiguous:
            effect = "unknown"
        elif self._terminal_seen == "ROLLED_BACK" and self._install_started:
            effect = "rolled_back"
        elif self._unchanged:
            effect = "unchanged"
        else:
            effect = "unknown" if self._install_started else "not_started"
        creation = self._creation["state"]
        if creation == "NEW":
            journal = "not_created"
        elif self._journal_clean or creation == "NO_EFFECT":
            journal = "clean"
        elif creation == "CREATED" and self.private_identity is not None:
            journal = "recovery_required"
        else:
            journal = "unknown"
        resources = "unknown" if self._guard is not None and self._guard.lifetime_ledger.fatal else "settled"
        current_reason = self._reason
        if current_reason == "none" and (effect == "unknown" or journal in {"unknown", "recovery_required"}
                                         or resources == "unknown"):
            current_reason = "custody_unknown" if resources == "unknown" else "filesystem_error"
        self._outcome = InitApplyOutcome(effect, journal, resources, current_reason)
        return self._outcome

    def _fixed_recovery(self) -> None:
        _require(not self._recovery_claimed, "original cleanup has already been attempted")
        self._recovery_claimed = True
        if self._creation["state"] != "CREATED" or self.private_identity is None:
            return
        _require(not self._original_controls_required or self._workflow_complete,
                 "incomplete original workflow preparation must be retained")
        _require(not self._terminal_ambiguous, "terminal publication is uncertain; preserve the journal")
        _require(self._terminal_seen != "COMMITTED" or self._terminal_durable,
                 "commit decision is known but durability is unconfirmed; preserve the journal")
        self._cleanup_mode = True
        try:
            # Explicit cleanup mode is essential: ordinary guard.check() throws
            # on cancellation even inside deferred(). No second recovery loop.
            with self._guard.deferred(check_on_exit=False):
                self._checkpoint()
                self.recover()
        finally:
            self._cleanup_mode = False

    def apply_typed(self, changes: list[tuple[ObservedFile, bytes | None]]) -> InitApplyOutcome:
        """Configuration-only facade; legacy CLI keeps its public API."""
        return self._apply_typed(changes, TypedEditProfile.CONFIGURATION)

    def apply_workflows_typed(self, changes: list[tuple[ObservedFile, bytes | None]]) -> InitApplyOutcome:
        """Four fixed generated callers: create absent or preserve, never replace."""
        return self._apply_typed(changes, TypedEditProfile.GITHUB_WORKFLOWS)

    def apply_metadata_text_typed(self, changes: list[tuple[ObservedFile, bytes | None]]) -> InitApplyOutcome:
        """Only original config-bound public text targets; never dependencies."""
        return self._apply_typed(changes, TypedEditProfile.METADATA_TEXT)

    def _apply_typed(self, changes: list[tuple[ObservedFile, bytes | None]],
                     profile: TypedEditProfile) -> InitApplyOutcome:
        if self._scope is None or self._guard is None or self._typed_claimed:
            raise InitOperationFailure(InitApplyOutcome("not_started", "not_created", "settled", "invalid_params"))
        self._typed_claimed = True
        if self._typed_profile is not profile:
            raise InitOperationFailure(InitApplyOutcome("not_started", "not_created", "settled", "invalid_params"))
        try:
            self._checkpoint()
            if profile is TypedEditProfile.METADATA_TEXT:
                from .init_workspace_custody import MetadataTargets, RootedRevision
                from .metadata_text import MAX_TEXT_BYTES
                targets = self._metadata_targets
                _require(type(targets) is MetadataTargets, "original metadata targets are required")
                targets._check_workspace(self)
                _require(type(self._rooted_revision) is RootedRevision
                         and self._scope.lease._revision is self._rooted_revision
                         and self._rooted_revision._metadata_targets is targets,
                         "metadata Apply requires its original rechecked revision")
                paths, limits = targets.paths, (MAX_TEXT_BYTES,) * len(targets.paths)
            elif profile in (TypedEditProfile.CONFIGURATION, TypedEditProfile.GITHUB_WORKFLOWS):
                paths, limits = profile.paths, profile.payload_limits
            else:
                raise InitOperationFailure(InitApplyOutcome("not_started", "not_created", "settled", "invalid_params"))
            _require(type(changes) is list and len(changes) == len(paths), "invalid desktop change count")
            for change, path, limit in zip(changes, paths, limits):
                _require(type(change) is tuple and len(change) == 2, "invalid desktop change")
                item, payload = change
                original = self._captured.get(path)
                _require(type(item) is ObservedFile and original is not None and item == original
                         and item.path == path and (payload is None or type(payload) is bytes and len(payload) <= limit),
                         "desktop changes do not match the original revision")
                if profile is TypedEditProfile.GITHUB_WORKFLOWS:
                    _require((item.before is not None and payload is None)
                             or (item.before is None and item.data is None and type(payload) is bytes and 0 < len(payload)),
                             "workflow changes cannot replace existing files or omit absent callers")
                elif profile is TypedEditProfile.METADATA_TEXT:
                    _require((item.before is not None and payload is None)
                             or type(payload) is bytes and 0 < len(payload),
                             "metadata changes cannot omit an absent required field")
            if profile is TypedEditProfile.GITHUB_WORKFLOWS:
                _require(set(self._captured) == set(paths) and tuple(sorted(self.parents)) == profile.directories,
                         "workflow capture is not the exact fixed domain")
            elif profile is TypedEditProfile.METADATA_TEXT:
                _require(set(self._captured) == set(targets.observation_paths)
                         and set(self.parents) == {"release", *targets.directories},
                         "metadata capture is not the original target/dependency domain")
            validate_paths(list(paths))
            self.require_clean()
            self._metadata_dependencies_check()
            for item, _ in changes:
                self._original_target_check(item, "input changed after revalidation")
            if all(payload is None for _, payload in changes):
                self._unchanged = True
                return self.current_outcome()
            # Capture/prepare do not bind ctypes symbols or perform fs probes.
            self.rename = _rename_function()
            plan = self._prepare(changes)
            with self._private(self._state_names[1]) as fd:
                self._installing = True
                try:
                    self._install(fd, plan)
                finally:
                    self._installing = False
            self._fixed_recovery()  # Exactly committed cleanup, never a rebuild.
        except BaseException as error:
            if self._primary is None:
                self._primary = error
                self._reason = (error.outcome.reason if type(error) is InitOperationFailure else
                                "cancelled" if isinstance(error, KeyboardInterrupt) else
                                "stale_revision" if isinstance(error, InitConflict) else "filesystem_error")
            if not self._recovery_claimed and not isinstance(error, InitConflict):
                try:
                    self._fixed_recovery()
                except BaseException:
                    # Preserve the first primary and actual irreversible facts.
                    # Independent original handle closes still run in the scope.
                    pass
            raise InitOperationFailure(self.current_outcome(), self._primary) from None
        return self.current_outcome()

    def recover(self) -> str:
        if self._typed_profile is TypedEditProfile.METADATA_TEXT:
            _require(self._scope is not None and self._cleanup_mode and self._recovery_claimed
                     and self._creation["state"] == "CREATED" and self._workflow_complete,
                     "metadata recovery belongs only to the original one-use transaction")
            self._metadata_dependencies_check()
        state = self.state()
        if state is None:
            return "no-op"
        if state == self._state_names[0]:
            with self._private(state) as fd:
                self._preparing_inventory(fd)
            result = "preparing-cleanup"
        elif state == self._state_names[1]:
            with self._private(state) as fd:
                plan = self._load(fd)
                terminal = self._terminal(fd, plan)
                self._inventory(fd, plan)
                if terminal is None:
                    self._rollback(fd, plan)
                    result = "rolled-back"
                else:
                    result = "committed-cleanup" if terminal == "COMMITTED" else "rolled-back-cleanup"
        elif state == self._state_names[2]:
            result = "cleanup-only"
        else:
            raise ValidationError("unrecognized transaction domain; preserve private state")
        if state != self._state_names[2]:
            self._state_move(state, self._state_names[2])
        self._cleanup()
        return result

    def apply(self, changes: list[tuple[ObservedFile, bytes | None]]) -> None:
        _require(self._typed_profile is not TypedEditProfile.METADATA_TEXT,
                 "metadata requires its original typed target facade, not legacy apply")
        validate_paths([item.path for item, _ in changes])
        _require(all(payload is None or type(payload) is bytes for _, payload in changes), "invalid staged content")
        self.require_clean()
        for item, _ in changes:
            _require(self._current(item.path) == item.before, "input changed after it was read")
        if all(payload is None for _, payload in changes):
            return
        terminal_seen = False
        try:
            plan = self._prepare(changes)
            with self._private(self._state_names[1]) as fd:
                self._install(fd, plan)
                terminal_seen = True
            self.recover()  # Committed cleanup only, never continuation/rebuild.
        except BaseException as original:
            if isinstance(original, InitConflict):
                raise ValidationError("init failed; recovery conflict: preserve private state and user edits before init --recover") from original
            detail = "original files restored"
            try:
                state = self.state()
                if state == self._state_names[1]:
                    with self._private(self._state_names[1]) as fd:
                        current_plan = self._load(fd)
                        terminal_seen = terminal_seen or self._terminal(fd, current_plan) == "COMMITTED"
                if state == self._state_names[2] or terminal_seen:
                    detail = "integration is terminal; cleanup/recovery may be incomplete"
                outcome = self.recover()
                if terminal_seen or outcome == "committed-cleanup":
                    detail = "complete integration was committed; inspect it, recovery is cleanup-only"
            except BaseException:
                detail = "automatic recovery incomplete; preserve the private transaction and user edits, then run init --recover"
            if isinstance(original, KeyboardInterrupt):
                raise InitInterrupted(f"init interrupted; {detail}") from original
            if not isinstance(original, Exception):
                raise
            raise ValidationError(f"init failed; {detail}") from original
