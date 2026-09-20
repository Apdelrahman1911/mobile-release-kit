"""Original files for the one saved Android AAB action; no command/tool runner.

This is source for review, not installed/native qualification. Only the original
AndroidBuildOperation can acquire these resources. Paths and observation DATA
never replace its live project/descriptor/iterator/creation records. Work-only
disposal is finite and requires genuinely settled consumers; artifacts remain
intentionally retained, with result eligibility decided by the operation.
"""
from __future__ import annotations

import errno
import hashlib
import os
import re
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterator

from .build_inputs import (
    BuildInputError, _FD, _StoreNamespace, _check_creation, _cleanup_failure, _direct_refusal,
    _directory, _file, _mkdir_private, _name_key,
)
from .config import MAX_CONFIG_BYTES, MAX_VERSION_BYTES
from .errors import ValidationError

READ_CHUNK = 64 * 1024
MAX_READ_RESULT = 16 * 1024 * 1024
MAX_AAB_BYTES = 1024**3
MAX_READ_BYTES = 8 * 1024**3
MAX_INPUT_BYTES = MAX_CONFIG_BYTES + MAX_VERSION_BYTES + 512 * 1024
MAX_OUTPUT_ENTRIES = 4096
MAX_OUTPUT_CANDIDATES = 32
MAX_NAME_BYTES = 2 * 1024 * 1024
MAX_RELATIVE_BYTES = 2048
MAX_WORK_ENTRIES = 100_000
MAX_WORK_DEPTH = 32
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_MODULE = re.compile(r":[0-9A-Za-z_.:-]{0,511}\Z")
_VARIANT = re.compile(r"[0-9A-Za-z_-]{1,128}\Z")
_OS_SCANDIR, _OS_UNLINK, _OS_RMDIR = os.scandir, os.unlink, os.rmdir
_SCAN_REFUSALS = {errno.ENOENT, errno.ENOTDIR, errno.EACCES, errno.EPERM,
                  errno.EBADF, errno.EMFILE, errno.ENFILE}
_DELETE_REFUSALS = {errno.ENOENT, errno.ENOTDIR, errno.EACCES, errno.EPERM,
                    errno.EROFS, errno.ENOTEMPTY, errno.EEXIST, errno.EBUSY}


class AndroidFileError(ValidationError):
    """Fixed reason only; never include a path, filename or OS exception text."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__("The original saved Android files could not be admitted")


class _RetainWork(Exception):
    """A known no-effect/bounded stop, not an unknown consuming operation."""


@dataclass(eq=False)
class _DirectoryRecord:
    parent: int
    name: str
    slot: _FD
    identity: dict[str, int] | None = None
    parent_record: _DirectoryRecord | None = None
    creation: dict[str, str] | None = None
    deleted: bool = False


@dataclass(eq=False)
class _FileRecord:
    parent: int
    name: str
    slot: _FD
    identity: dict[str, int] | None = None
    parent_record: _DirectoryRecord | None = None
    deleted: bool = False


@dataclass(eq=False)
class _InputRecord:
    relative: str
    limit: int
    parent: int | None = None
    name: str | None = None
    parent_record: _DirectoryRecord | None = None
    file: _FileRecord | None = None
    absent: bool = False
    complete: bool = False
    raw: bytes | None = None
    sha256: str | None = None


class _DirectoryIterator:
    """An original prearmed scandir record, including failed acquisitions."""

    def __init__(self, files: AndroidBuildFiles, *, cleanup: bool) -> None:
        self.files, self.cleanup = files, cleanup
        self.value = None
        self.state, self.close_state = "NEW", "NOT_ATTEMPTED"

    def acquire(self, number: int) -> None:
        self.files._point(cleanup=self.cleanup)
        self.files._require(self.state == "NEW", "project-admission-refused")
        operation = os.scandir
        with self.files.guard.deferred(check_on_exit=False):
            try:
                self.state = "ATTEMPTED"
                self.value = operation(number)
                if (self.value is None or not callable(getattr(type(self.value), "__next__", None))
                        or not callable(getattr(type(self.value), "close", None))):
                    raise AndroidFileError("cleanup-unknown")
                self.state = "OPEN"
            except BaseException as error:
                self.state = "NO_EFFECT" if _direct_refusal(
                    error, operation, _OS_SCANDIR, _DirectoryIterator.acquire.__code__,
                    _SCAN_REFUSALS) else "UNKNOWN"
                self.files._remember(error)
                if self.state == "UNKNOWN":
                    self.files._unknown(error)
                raise

    def advance(self):
        self.files._point(cleanup=self.cleanup)
        self.files._charge("file-iterator-advances", 1, 400_000, cleanup=self.cleanup)
        self.files._require(self.state == "OPEN" and self.close_state == "NOT_ATTEMPTED"
                            and self.value is not None, "project-admission-refused")
        value = next(self.value)
        self.files._point(cleanup=self.cleanup)
        return value

    def close(self) -> None:
        self.files._owner()
        if self.close_state == "CLOSED":
            return
        if self.close_state != "NOT_ATTEMPTED" or self.state in {"ATTEMPTED", "UNKNOWN"}:
            self.files._unknown(AndroidFileError("cleanup-unknown"))
        with self.files.guard.deferred(check_on_exit=False):
            try:
                self.close_state = "ATTEMPTED"
                if self.value is not None:
                    if self.value.close() is not None:
                        raise AndroidFileError("cleanup-unknown")
                self.close_state = "CLOSED"
            except BaseException as error:
                self.close_state = "UNKNOWN"
                self.files._remember(error)
                self.files._unknown(error)


@dataclass(eq=False)
class _DeleteRecord:
    """A named consuming operation, registered before its sole attempt."""

    files: AndroidBuildFiles
    original: _DirectoryRecord | _FileRecord
    directory: bool
    state: str = "NEW"

    def remove(self) -> None:
        files, original = self.files, self.original
        files._point(cleanup=True)
        files._require_consumers()
        files._require(self.state == "NEW", "cleanup-unknown")
        files._check_record(original, cleanup=True)
        operation = os.rmdir if self.directory else os.unlink
        builtin = _OS_RMDIR if self.directory else _OS_UNLINK
        with files.guard.deferred(check_on_exit=False):
            self.state = "ATTEMPTED"
            try:
                result = operation(original.name, dir_fd=original.parent)
            except BaseException as error:
                # Only the actual consuming call can establish NO_EFFECT.
                # Later verification has a different meaning even if a direct
                # stat/fstat raises the same documented errno in this frame.
                self.state = "NO_EFFECT" if _direct_refusal(
                    error, operation, builtin, _DeleteRecord.remove.__code__,
                    _DELETE_REFUSALS) else "UNKNOWN"
                files._remember(error)
                if self.state == "NO_EFFECT":
                    raise _RetainWork() from None
                files._unknown(error)
            try:
                if result is not None:
                    raise AndroidFileError("cleanup-unknown")
                # Positive return plus the retained original inode losing its
                # last name; never reopen/adopt a replacement as the receipt.
                number = original.slot.number
                if number is None:
                    raise AndroidFileError("cleanup-unknown")
                after = os.fstat(number)
                identity = _directory(after) if self.directory else _file(after)
                ignored = set() if self.directory else {"ctime", "links"}
                if (after.st_nlink != 0 or original.identity is None
                        or any(identity[key] != original.identity[key] for key in identity if key not in ignored)):
                    raise AndroidFileError("cleanup-unknown")
                try:
                    os.stat(original.name, dir_fd=original.parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise AndroidFileError("cleanup-unknown")
                original.deleted = True
                self.state = "DELETED"
            except BaseException as error:
                self.state = "UNKNOWN"
                files._remember(error)
                files._unknown(error)


@dataclass(eq=False)
class _WorkFrame:
    directory: _DirectoryRecord
    iterator: _DirectoryIterator
    depth: int
    keys: set[str] = field(default_factory=set)


class _BorrowedReader:
    """No fd close/open, descriptor escape, pathname fallback or read-all."""

    def __init__(self, artifact: OriginalAndroidArtifact) -> None:
        self.artifact = artifact
        self.position = 0
        self.closed = False

    def _check(self) -> None:
        artifact = self.artifact
        artifact.files._require(not self.closed and artifact._reader is self,
                                "artifact-changed")
        artifact.check()

    def tell(self) -> int:
        self._check()
        return self.position

    def seek(self, offset: int, whence: int = 0) -> int:
        self._check()
        files, artifact = self.artifact.files, self.artifact
        files._require(type(offset) is int and type(whence) is int and whence in (0, 1, 2),
                       "artifact-unsafe")
        base = (0, self.position, artifact.size)[whence]
        target = base + offset
        files._require(0 <= target <= artifact.size, "artifact-unsafe")
        self.position = target
        return target

    def readable(self) -> bool:
        self._check()
        return True

    def seekable(self) -> bool:
        self._check()
        return True

    def read(self, amount: int = -1) -> bytes:
        self._check()
        artifact, files = self.artifact, self.artifact.files
        files._require(type(amount) is int and amount >= -1, "artifact-unsafe")
        remaining = artifact.size - self.position
        requested = remaining if amount == -1 else min(amount, remaining)
        files._require(requested <= MAX_READ_RESULT, "input-limit")
        if not requested:
            self._check()
            return b""
        number = artifact._snapshot.slot.number
        files._require(number is not None, "artifact-changed")
        files._seek(number, self.position)
        blocks: list[bytes] = []
        consumed = 0
        while consumed < requested:
            self._check()
            block = files._read(number, min(READ_CHUNK, requested - consumed))
            files._require(bool(block), "artifact-changed")
            consumed += len(block)
            self.position += len(block)
            blocks.append(block)
            self._check()
        files._point()
        return b"".join(blocks)


class OriginalAndroidArtifact:
    """The original fixed snapshot, not a serializable Path/digest capability."""

    logical_name = "android-aab"
    file_name = "app-release.aab"
    freshness = "not-established"

    def __init__(self, files: AndroidBuildFiles, source: _FileRecord,
                 snapshot: _FileRecord, *, size: int, sha256: str) -> None:
        files._require(files._capture_claimed and files.artifact is None
                       and files._snapshot is snapshot
                       and any(record is source for record in files.file_records),
                       "artifact-unsafe")
        self.files, self._source, self._snapshot = files, source, snapshot
        self.size, self.sha256 = size, sha256
        self._reader: _BorrowedReader | None = None
        self._native = False
        self._borrows: list[_BorrowedReader] = []

    @property
    def path(self) -> Path:
        self.check()
        assert self.files.namespace is not None
        return self.files.namespace.path / "artifacts" / self.file_name

    def check(self) -> None:
        files = self.files
        files._point()
        files._require(type(self) is OriginalAndroidArtifact and files.artifact is self
                       and files._original_artifact is self
                       and not files.close_claimed and self._snapshot.identity is not None
                       and self._snapshot.identity["size"] == self.size,
                       "artifact-changed")
        files._namespace_metadata()
        files._check_output_scope()
        files._check_record(self._source)
        files._check_record(self._snapshot)

    def verify_bytes(self) -> None:
        self.check()
        self.files._require(self._reader is None, "artifact-changed")
        self.files._require(self.files._digest(self._snapshot, self.size) == self.sha256,
                            "artifact-changed")
        self.check()

    @contextmanager
    def reader(self) -> Iterator[_BorrowedReader]:
        self.check()
        files = self.files
        files._require(self._reader is None and not self._native
                       and not files.operation.close_claimed, "artifact-changed")
        files._charge("artifact-reader-borrows", 1, 16)
        reader = _BorrowedReader(self)
        self._borrows.append(reader)  # Retain the original before publishing it.
        self._reader = reader
        primary = None
        try:
            yield reader
        except BaseException as error:
            primary = error
            files._remember(error)
            raise
        finally:
            try:
                files._require(self._reader is reader, "cleanup-unknown")
                reader.closed = True
                self._reader = None
                self.check()
            except BaseException as error:
                files._remember(error)
                if primary is None:
                    raise

    @contextmanager
    def native_input(self) -> Iterator[Path]:
        self.check()
        files = self.files
        files._require(not self._native and self._reader is None
                       and not files.operation.close_claimed, "artifact-changed")
        files._charge("artifact-native-borrows", 1, 1)
        self.verify_bytes()
        self._native = True
        primary = None
        try:
            yield self.path
        except BaseException as error:
            primary = error
            files._remember(error)
            raise
        finally:
            try:
                # A returned Python scope alone does not settle an original
                # native consumer. Unknown consumers retain this borrow.
                files._require_consumers()
                # Settlement retires the consuming borrow even if the original
                # post-read finds drift or a prior failure prevents publication.
                # Its failed verification is not a living native consumer.
                self._native = False
                with files.guard.deferred(check_on_exit=False):
                    self.verify_bytes()
            except BaseException as error:
                files._remember(error)
                if primary is None:
                    raise


class AndroidBuildFiles:
    """One narrow original file roster; no generic runner or cleanup callback."""

    def __init__(self, operation) -> None:
        from .android_build_operation import AndroidBuildOperation
        if type(operation) is not AndroidBuildOperation:
            raise AndroidFileError("project-admission-refused")
        operation.owner()
        self.operation, self.guard, self.source = operation, operation.guard, operation.source
        self.root = operation.root
        self.pid, self.thread, self.uid = os.getpid(), threading.current_thread(), os.geteuid()
        self.namespace: _StoreNamespace | None = None
        self._namespace_owner: _StoreNamespace | None = None
        self.artifact: OriginalAndroidArtifact | None = None
        self._original_artifact: OriginalAndroidArtifact | None = None
        self._invocation = self._project = None
        self._root_number: int | None = None
        self._root_identity: dict[str, int] | None = None
        self.slots: list[_FD] = []
        self.iterators: list[_DirectoryIterator] = []
        self.directories: list[_DirectoryRecord] = []
        self.file_records: list[_FileRecord] = []
        self.deletions: list[_DeleteRecord] = []
        self.inputs: dict[str, _InputRecord] = {}
        self._input_directories: dict[tuple[str, ...], _DirectoryRecord] = {}
        self._numbers: dict[int, _FD] = {}
        self._work: _DirectoryRecord | None = None
        self._artifacts: _DirectoryRecord | None = None
        self._snapshot: _FileRecord | None = None
        self._output_scope: _DirectoryRecord | None = None
        self._output_epoch: tuple[int, int] | None = None
        self._capture_claimed = self._work_claimed = self.close_claimed = False
        self._close_complete = self._unknown_seen = False
        self._cleanup_counts: dict[str, int] = {}

    def _owner(self) -> None:
        from .android_build_operation import AndroidBuildOperation
        operation = self.operation
        if (type(operation) is not AndroidBuildOperation or operation.files is not self
                or self.pid != os.getpid() or self.thread is not threading.current_thread()
                or self.uid != os.geteuid() or operation.guard is not self.guard
                or operation.source is not self.source or operation.root != self.root
                or self.source.operation is not operation or self.source.guard is not self.guard):
            raise AndroidFileError("project-admission-refused")
        operation.owner()

    def _point(self, *, cleanup: bool = False) -> None:
        self._owner()
        if cleanup or self.guard.depth:
            self.operation.cleanup_checkpoint()
        else:
            self._require(not self.close_claimed, "project-admission-refused")
            self.operation.charge("file-checkpoints", 1, 4_000_000)

    def _charge(self, name: str, amount: int, limit: int, *, cleanup: bool = False) -> None:
        self._owner()
        if cleanup:
            self.operation.cleanup_checkpoint()
            previous = self._cleanup_counts.get(name, 0)
            if type(amount) is not int or amount < 0 or previous > limit - amount:
                raise _RetainWork() from None
            self._cleanup_counts[name] = previous + amount
        else:
            self.operation.charge(name, amount, limit)

    def _require(self, condition: bool, reason: str) -> None:
        if not condition:
            if reason == "cleanup-unknown":
                self._unknown(AndroidFileError(reason))
            self.operation.fail(reason)
            raise AndroidFileError(reason)  # A returning fail hook grants nothing.

    def _remember(self, error: BaseException) -> None:
        self.guard.lifetime_ledger._remember(error)

    def _unknown(self, error: BaseException) -> None:
        self._unknown_seen = True
        raise _cleanup_failure(self.guard, error) from None

    def _require_consumers(self) -> None:
        self._owner()
        facts = self.guard.lifetime_ledger.verdict()
        if not facts.complete or not facts.contained:
            self._unknown(AndroidFileError("cleanup-unknown"))

    def _borrow_root(self) -> int:
        self._point()
        invocation = self.operation.invocation
        self._require(invocation is not None, "project-admission-refused")
        number, binding = invocation._android_build_root(self.operation)
        self._require(binding == self.operation.request.native["rootIdentity"],
                      "project-admission-refused")
        identity = _directory(os.fstat(number))
        if self._root_number is None:
            self._invocation, self._project = invocation, invocation._original_project
            self._root_number, self._root_identity = number, identity
        self._require(self._invocation is invocation and self._project is invocation._original_project
                      and self._root_number == number and self._root_identity == identity,
                      "project-admission-refused")
        self._root_metadata()
        return number

    def _root_metadata(self) -> None:
        """No re-enumeration/hash per 64KiB chunk and no renewed admission."""
        self._owner()
        invocation, project = self._invocation, self._project
        self._require(invocation is not None and invocation is self.operation.invocation
                      and project is not None and project is invocation._original_project
                      and project is invocation.project_owner and not project.claimed
                      and invocation.child is None and invocation.signing_lease is None
                      and self._root_number is not None,
                      "project-admission-refused")
        invocation._owner()
        project.directory.check()
        self._require(project.fd == self._root_number
                      and _directory(os.fstat(self._root_number)) == self._root_identity,
                      "project-admission-refused")

    def _namespace_metadata(self) -> None:
        self._root_metadata()
        namespace = self.namespace
        self._require(type(namespace) is _StoreNamespace and namespace is self._namespace_owner
                      and namespace.android_operation is self.operation
                      and namespace.parent_acquired and not namespace.claimed,
                      "project-admission-refused")
        parent = self._root_number
        for name, slot, identity in zip(namespace.components, namespace.slots, namespace.identities):
            self._require(identity is not None and slot.number is not None
                          and _directory(os.fstat(slot.number)) == identity
                          and _directory(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity,
                          "project-admission-refused")
            parent = slot.number

    def _known_number(self, number: int) -> None:
        self._require(type(number) is int and number >= 0, "project-admission-refused")
        if number in self._numbers and self._numbers[number].number == number:
            return
        invocation = self.operation.invocation
        project = None if invocation is None else invocation._original_project
        if project is not None and project is invocation.project_owner:
            if any(slot.number == number for slot in (*project.directory.slots, project.meta)):
                return
        if (self.namespace is not None and self.namespace is self._namespace_owner
                and self.namespace.android_operation is self.operation):
            if any(slot.number == number for slot in self.namespace.slots):
                return
        self._require(False, "project-admission-refused")

    def _new_slot(self, *, cleanup: bool = False) -> _FD:
        self._charge("file-slots", 1, MAX_WORK_ENTRIES + 1024, cleanup=cleanup)
        slot = _FD(self.guard)
        self.slots.append(slot)
        return slot

    def _open(self, slot: _FD, name: str, flags: int, parent: int) -> int:
        self._known_number(parent)
        try:
            return slot.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        finally:
            if slot.number is not None:
                self._require(slot.number not in self._numbers, "cleanup-unknown")
                self._numbers[slot.number] = slot

    def _close_slot(self, slot: _FD) -> None:
        number = slot.number
        try:
            slot.close()
        finally:
            if number is not None and self._numbers.get(number) is slot:
                del self._numbers[number]

    def _new_iterator(self, number: int, *, cleanup: bool = False) -> _DirectoryIterator:
        self._known_number(number)
        self._charge("file-iterators", 1, MAX_WORK_ENTRIES + 4096, cleanup=cleanup)
        original = _DirectoryIterator(self, cleanup=cleanup)
        self.iterators.append(original)
        original.acquire(number)
        return original

    def _name(self, name: str, *, cleanup: bool = False, work: bool = False) -> str:
        valid = type(name) is str and 1 <= len(name) <= MAX_RELATIVE_BYTES and name not in (".", "..")
        valid = valid and not any(character in name for character in ("/", "\\", "\0"))
        if not valid:
            if cleanup:
                raise _RetainWork() from None
            self._require(False, "project-admission-refused")
        # Bounded preparation precedes Unicode normalization/encoding; actual
        # retained spelling/key bytes have their smaller independent ceiling.
        self._charge("work-name-preparation" if work else "file-name-preparation",
                     16 * len(name), 16 * MAX_NAME_BYTES, cleanup=cleanup)
        try:
            encoded = name.encode("utf-8")
            key = _name_key(name)
            key_bytes = key.encode("utf-8")
        except UnicodeError:
            if cleanup:
                raise _RetainWork() from None
            self._require(False, "project-admission-refused")
            raise AssertionError("unreachable") from None
        if len(encoded) > MAX_RELATIVE_BYTES or len(key_bytes) > MAX_RELATIVE_BYTES:
            if cleanup:
                raise _RetainWork() from None
            self._require(False, "input-limit")
        self._charge("work-name-bytes" if work else "file-name-bytes",
                     len(encoded) + len(key_bytes), MAX_NAME_BYTES, cleanup=cleanup)
        return key

    def names(self, fd: int, limit: int = MAX_OUTPUT_ENTRIES) -> set[str]:
        """Used by original Project/namespace checks; never os.listdir/glob."""
        self._point(cleanup=bool(self.guard.depth))
        self._require(type(limit) is int and 0 <= limit <= MAX_OUTPUT_ENTRIES,
                      "input-limit")
        self._known_number(fd)
        before = os.fstat(fd)
        self._require(stat.S_ISDIR(before.st_mode), "project-admission-refused")
        iterator = self._new_iterator(fd, cleanup=bool(self.guard.depth))
        result, keys = set(), set()
        primary = None
        try:
            while True:
                try:
                    entry = iterator.advance()
                except StopIteration:
                    break
                self._require(len(result) < limit, "input-limit")
                key = self._name(entry.name, cleanup=bool(self.guard.depth))
                self._require(key not in keys, "project-admission-refused")
                keys.add(key)
                result.add(entry.name)
            after = os.fstat(fd)
            self._require(_directory(before) == _directory(after)
                          and (before.st_mtime_ns, before.st_ctime_ns)
                          == (after.st_mtime_ns, after.st_ctime_ns), "project-admission-refused")
            return result
        except BaseException as error:
            primary = error
            self._remember(error)
            raise
        finally:
            try:
                iterator.close()
            except BaseException as error:
                self._remember(error)
                if primary is None:
                    raise

    def _parts(self, relative: str) -> tuple[str, ...]:
        self._require(type(relative) is str and 1 <= len(relative) <= MAX_RELATIVE_BYTES,
                      "project-admission-refused")
        self._charge("relative-path-bytes", 4 * len(relative), MAX_NAME_BYTES)
        path = PurePosixPath(relative)
        self._require(not path.is_absolute() and path.as_posix() == relative
                      and 1 <= len(path.parts) <= 64 and "\\" not in relative
                      and "\0" not in relative
                      and all(part not in ("", ".", "..", ".git", ".mobile-release") for part in path.parts),
                      "project-admission-refused")
        try:
            length = len(relative.encode("utf-8"))
        except UnicodeError:
            self._require(False, "project-admission-refused")
            raise AssertionError("unreachable") from None
        self._require(length <= MAX_RELATIVE_BYTES, "input-limit")
        return path.parts

    def _check_record(self, record: _DirectoryRecord | _FileRecord, *, cleanup: bool = False,
                      reason: str = "artifact-changed") -> None:
        self._point(cleanup=cleanup)
        reason = "work-retained" if cleanup else reason
        chain, parent = [], record.parent_record
        while parent is not None:
            self._require(len(chain) <= 64, "artifact-unsafe")
            chain.append(parent)
            parent = parent.parent_record
        for item in (*reversed(chain), record):
            self._require(item.identity is not None and item.slot.number is not None and not item.deleted,
                          reason)
            self._require(self._numbers.get(item.slot.number) is item.slot, "cleanup-unknown")
            identity = _directory if type(item) is _DirectoryRecord else _file
            self._require(identity(os.fstat(item.slot.number)) == item.identity
                          and identity(os.stat(item.name, dir_fd=item.parent, follow_symlinks=False)) == item.identity,
                          reason)

    def _directory_at(self, parent: int, name: str, parent_record=None,
                      *, cleanup: bool = False, reason: str = "artifact-unsafe") -> _DirectoryRecord:
        self._point(cleanup=cleanup)
        record = _DirectoryRecord(parent, name, self._new_slot(cleanup=cleanup),
                                  parent_record=parent_record)
        self.directories.append(record)
        number = self._open(record.slot, name, os.O_RDONLY | os.O_DIRECTORY, parent)
        record.identity = _directory(os.fstat(number))
        identity = record.identity
        self._require(identity["uid"] == self.uid and identity["device"] == os.fstat(parent).st_dev
                      and not identity["mode"] & 0o7022,
                      "work-retained" if cleanup else reason)
        self._check_record(record, cleanup=cleanup, reason=reason)
        return record

    def _file_at(self, parent: int, name: str, parent_record=None, *, cleanup: bool = False,
                 reason: str = "artifact-unsafe") -> _FileRecord:
        self._point(cleanup=cleanup)
        record = _FileRecord(parent, name, self._new_slot(cleanup=cleanup), parent_record=parent_record)
        self.file_records.append(record)
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        self._require(stat.S_ISREG(before.st_mode), "work-retained" if cleanup else reason)
        number = self._open(record.slot, name, os.O_RDONLY, parent)
        record.identity = _file(os.fstat(number))
        identity = record.identity
        self._require(identity == _file(before) and identity["uid"] == self.uid
                      and identity["device"] == os.fstat(parent).st_dev
                      and identity["links"] == 1 and not identity["mode"] & 0o7022,
                      "work-retained" if cleanup else reason)
        self._check_record(record, cleanup=cleanup, reason=reason)
        return record

    def _seek(self, number: int, offset: int) -> None:
        self._point()
        self._known_number(number)
        self._require(os.lseek(number, offset, os.SEEK_SET) == offset, "artifact-changed")
        self._point()

    def _read(self, number: int, amount: int) -> bytes:
        self._require(type(amount) is int and 0 < amount <= READ_CHUNK, "input-limit")
        self._known_number(number)
        self._charge("file-read-calls", 1, 262_144)
        self._charge("file-read-bytes", amount, MAX_READ_BYTES)
        value = os.read(number, amount)
        self._point()
        self._require(type(value) is bytes and len(value) <= amount, "artifact-changed")
        return value

    def _digest(self, record: _FileRecord, size: int, *, reason: str = "artifact-changed") -> str:
        self._check_record(record, reason=reason)
        number = record.slot.number
        self._require(number is not None, "artifact-changed")
        self._seek(number, 0)
        digest, consumed = hashlib.sha256(), 0
        while consumed < size:
            self._check_record(record, reason=reason)
            block = self._read(number, min(READ_CHUNK, size - consumed))
            self._require(bool(block), reason)
            consumed += len(block)
            digest.update(block)
        self._require(not self._read(number, 1), reason)
        self._check_record(record, reason=reason)
        return digest.hexdigest()

    def _input_check(self, record: _InputRecord) -> None:
        self._root_metadata()
        self._require(record.complete and record.parent is not None and record.name is not None,
                      "project-admission-refused")
        if record.parent_record is not None:
            self._check_record(record.parent_record, reason="project-admission-refused")
        names = self.names(record.parent)
        key = _name_key(record.name)
        self._require(all(_name_key(name) != key or name == record.name for name in names),
                      "project-admission-refused")
        if record.absent:
            self._require(record.name not in names, "project-admission-refused")
        else:
            self._require(record.file is not None and record.raw is not None
                          and self._digest(record.file, len(record.raw), reason="project-admission-refused") == record.sha256,
                          "project-admission-refused")

    def read_input(self, relative: str, limit: int, optional: bool = False) -> bytes | None:
        self._point()
        self._require(not self.close_claimed and not self.operation.close_claimed,
                      "project-admission-refused")
        self._require(type(limit) is int and 0 < limit <= MAX_CONFIG_BYTES
                      and type(optional) is bool, "input-limit")
        parts = self._parts(relative)
        parent = self._borrow_root()
        if relative in self.inputs:
            existing = self.inputs[relative]
            self._input_check(existing)
            self._require(existing.raw is None or len(existing.raw) <= limit, "input-limit")
            self._require(optional or existing.raw is not None, "project-admission-refused")
            return existing.raw
        self._charge("saved-input-files", 1, 16)
        record = _InputRecord(relative, limit)
        self.inputs[relative] = record
        parent_record = None
        for index, name in enumerate(parts):
            names = self.names(parent)
            self._require(all(_name_key(item) != _name_key(name) or item == name for item in names),
                          "project-admission-refused")
            record.parent, record.name, record.parent_record = parent, name, parent_record
            if name not in names:
                record.absent = record.complete = True
                self._require(optional, "project-admission-refused")
                return None
            if index == len(parts) - 1:
                break
            key = parts[:index + 1]
            if key not in self._input_directories:
                self._input_directories[key] = self._directory_at(
                    parent, name, parent_record, reason="project-admission-refused")
            parent_record = self._input_directories[key]
            self._check_record(parent_record, reason="project-admission-refused")
            parent = parent_record.slot.number
        original = self._file_at(parent, parts[-1], parent_record, reason="project-admission-refused")
        record.file = original
        assert original.identity is not None and original.slot.number is not None
        size = original.identity["size"]
        self._require(0 <= size <= limit, "input-limit")
        self._charge("saved-input-bytes", size, MAX_INPUT_BYTES)
        blocks, consumed, digest = [], 0, hashlib.sha256()
        while consumed < size:
            self._check_record(original, reason="project-admission-refused")
            block = self._read(original.slot.number, min(READ_CHUNK, size - consumed))
            self._require(bool(block), "project-admission-refused")
            consumed += len(block)
            digest.update(block)
            blocks.append(block)
        self._require(not self._read(original.slot.number, 1), "project-admission-refused")
        self._check_record(original, reason="project-admission-refused")
        record.raw, record.sha256 = b"".join(blocks), digest.hexdigest()
        record.complete = True
        self._input_check(record)
        return record.raw

    def check_inputs(self) -> None:
        self._point()
        if self.inputs:
            self._borrow_root()
        for record in self.inputs.values():
            self._input_check(record)

    def prepare_namespace(self) -> None:
        self._point()
        self._require(not self.close_claimed and not self.operation.close_claimed
                      and self.namespace is None and _TOKEN.fullmatch(self.operation.operation_id) is not None,
                      "project-admission-refused")
        self._borrow_root()
        namespace = _StoreNamespace(
            self.root, self.guard, include_store=False,
            _descendants=("desktop-android-build", self.operation.operation_id),
            _exclusive_index=2, _android_operation=self.operation,
        )
        self.namespace = self._namespace_owner = namespace  # Before mkdir/open/ensure_meta.
        namespace.acquire()
        self._namespace_metadata()
        parent = namespace.slots[-1].number
        self._require(parent is not None and not self.names(parent), "project-admission-refused")
        self._work = _DirectoryRecord(parent, "work", self._new_slot(), creation={"state": "NEW"})
        self.directories.append(self._work)
        self._artifacts = _DirectoryRecord(parent, "artifacts", self._new_slot(), creation={"state": "NEW"})
        self.directories.append(self._artifacts)
        for record in (self._work, self._artifacts):
            self._point()
            names = self.names(parent)
            self._require(all(_name_key(name) != record.name for name in names),
                          "project-admission-refused")
            _mkdir_private(record.name, parent, self.guard, record.creation)
            number = self._open(record.slot, record.name, os.O_RDONLY | os.O_DIRECTORY, parent)
            record.identity = _directory(os.fstat(number))
            self._require(record.identity["uid"] == self.uid and record.identity["mode"] == 0o700
                          and record.identity["device"] == os.fstat(parent).st_dev,
                          "project-admission-refused")
            self._check_record(record, reason="project-admission-refused")
            os.fsync(parent)
        self._namespace_metadata()

    @property
    def work_path(self) -> Path:
        self._point()
        self._namespace_metadata()
        self._require(not self.close_claimed and not self.operation.close_claimed
                      and self._work is not None and not self._work_claimed,
                      "project-admission-refused")
        self._check_record(self._work, reason="project-admission-refused")
        assert self.namespace is not None
        return self.namespace.path / "work"

    def capture_aab(self, module: str, variant: str) -> OriginalAndroidArtifact:
        self._point()
        self._require(not self.close_claimed and not self.operation.close_claimed, "artifact-unsafe")
        self.operation.capture_ready(module, variant)
        self._require(not self._capture_claimed and self.artifact is None, "artifact-unsafe")
        self._capture_claimed = True
        self._require(type(module) is str and _MODULE.fullmatch(module) is not None
                      and type(variant) is str and _VARIANT.fullmatch(variant) is not None,
                      "artifact-unsafe")
        components = () if module == ":" else tuple(module[1:].split(":"))
        self._require(all(part not in ("", ".", "..") for part in components), "artifact-unsafe")
        relative = "/".join((*components, "build", "outputs", "bundle", variant))
        parts = self._parts(relative)
        self._namespace_metadata()
        self._require(self._artifacts is not None, "artifact-unsafe")
        self._check_record(self._artifacts)
        parent, parent_record = self._borrow_root(), None
        for name in parts:
            names = self.names(parent)
            self._require(all(_name_key(item) != _name_key(name) or item == name for item in names),
                          "artifact-unsafe")
            self._require(name in names, "artifact-missing")
            parent_record = self._directory_at(parent, name, parent_record)
            parent = parent_record.slot.number
        # Direct configured variant directory only. No nested search, baseline,
        # project wrapper execution or normalized-output fallback is available.
        # Discovery depth inside this allowed subtree is zero (maximum eight);
        # the preceding ancestors are the fixed bounded configured path only.
        observed_scope = os.fstat(parent)
        self._output_scope = parent_record
        self._output_epoch = observed_scope.st_mtime_ns, observed_scope.st_ctime_ns
        candidates = []
        for name in self.names(parent):
            self._charge("output-entries", 1, MAX_OUTPUT_ENTRIES)
            self._require(len((relative + "/" + name).encode("utf-8")) <= MAX_RELATIVE_BYTES,
                          "input-limit")
            observed = os.stat(name, dir_fd=parent, follow_symlinks=False)
            self._require((stat.S_ISREG(observed.st_mode) or stat.S_ISDIR(observed.st_mode))
                          and observed.st_uid == self.uid and observed.st_dev == os.fstat(parent).st_dev
                          and (not stat.S_ISREG(observed.st_mode) or observed.st_nlink == 1)
                          and not stat.S_IMODE(observed.st_mode) & 0o7022,
                          "artifact-unsafe")
            if name.casefold().endswith(".aab"):
                self._charge("output-candidates", 1, MAX_OUTPUT_CANDIDATES)
                self._require(name.endswith(".aab") and stat.S_ISREG(observed.st_mode), "artifact-unsafe")
                candidates.append(name)
        self._check_record(parent_record)
        self._check_output_scope()
        self._require(bool(candidates), "artifact-missing")
        self._require(len(candidates) == 1, "artifact-ambiguous")
        original = self._file_at(parent, candidates[0], parent_record)
        assert original.identity is not None and original.slot.number is not None
        size = original.identity["size"]
        self._require(0 < size <= MAX_AAB_BYTES, "artifact-unsafe")
        self._charge("captured-aab-bytes", size, MAX_AAB_BYTES)
        destination = self._artifacts.slot.number
        self._require(destination is not None and not self.names(destination), "artifact-unsafe")
        snapshot = _FileRecord(destination, "app-release.aab", self._new_slot(),
                               parent_record=self._artifacts)
        self._snapshot = snapshot
        self.file_records.append(snapshot)
        number = self._open(snapshot.slot, snapshot.name,
                            os.O_RDWR | os.O_CREAT | os.O_EXCL, destination)
        initial = _file(os.fstat(number))
        self._require(initial["uid"] == self.uid and initial["mode"] == 0o600
                      and initial["links"] == 1 and initial["size"] == 0
                      and initial["device"] == self._artifacts.identity["device"], "artifact-unsafe")
        snapshot.identity = initial  # Even an incomplete copy retains its original inode.
        digest, consumed = hashlib.sha256(), 0
        while consumed < size:
            self._check_record(original)
            block = self._read(original.slot.number, min(READ_CHUNK, size - consumed))
            self._require(bool(block), "artifact-changed")
            consumed += len(block)
            digest.update(block)
            view = memoryview(block)
            while view:
                self._charge("capture-write-bytes", len(view), MAX_AAB_BYTES)
                written = os.write(number, view)
                self._point()
                self._require(type(written) is int and 0 < written <= len(view), "artifact-changed")
                view = view[written:]
        self._require(not self._read(original.slot.number, 1), "artifact-changed")
        self._check_record(original)
        os.fsync(number)
        final = _file(os.fstat(number))
        self._require(all(final[key] == initial[key] for key in ("device", "inode", "uid", "gid", "mode", "links"))
                      and final["size"] == size, "artifact-changed")
        snapshot.identity = final
        self._check_record(snapshot)
        os.fsync(destination)
        artifact = OriginalAndroidArtifact(self, original, snapshot, size=size, sha256=digest.hexdigest())
        self.artifact = self._original_artifact = artifact
        artifact.verify_bytes()
        return artifact

    def _check_output_scope(self) -> None:
        self._require(self._output_scope is not None and self._output_epoch is not None,
                      "artifact-changed")
        self._check_record(self._output_scope)
        observed = os.fstat(self._output_scope.slot.number)
        self._require((observed.st_mtime_ns, observed.st_ctime_ns) == self._output_epoch,
                      "artifact-changed")

    def _work_delete(self, original: _DirectoryRecord | _FileRecord) -> None:
        self._charge("work-deletions", 1, MAX_WORK_ENTRIES + 1, cleanup=True)
        record = _DeleteRecord(self, original, type(original) is _DirectoryRecord)
        self.deletions.append(record)
        record.remove()
        self._close_slot(original.slot)

    def finish_work(self) -> None:
        self._point(cleanup=True)
        self._require(not self._work_claimed, "work-retained")
        self._work_claimed = True
        work = self._work
        if work is None or work.creation["state"] in ("NEW", "NO_EFFECT"):
            return
        self._require_consumers()
        if self.artifact is not None and (self.artifact._reader is not None or self.artifact._native):
            self._unknown(AndroidFileError("cleanup-unknown"))
        self._namespace_metadata()
        self._check_record(work, cleanup=True)
        stack: list[_WorkFrame] = []
        primary = None
        try:
            assert work.slot.number is not None
            iterator = self._new_iterator(work.slot.number, cleanup=True)
            stack.append(_WorkFrame(work, iterator, 0))
            while stack:
                self._point(cleanup=True)
                frame = stack[-1]
                self._check_record(frame.directory, cleanup=True)
                try:
                    entry = frame.iterator.advance()
                except StopIteration:
                    frame.iterator.close()
                    self._work_delete(frame.directory)
                    stack.pop()
                    continue
                self._charge("work-entries", 1, MAX_WORK_ENTRIES, cleanup=True)
                # A work-name limit must not exhaust the independent bounded
                # namespace identity checks used to close original handles.
                key = self._name(entry.name, cleanup=True, work=True)
                if key in frame.keys:
                    raise _RetainWork() from None
                frame.keys.add(key)
                number = frame.directory.slot.number
                observed = os.stat(entry.name, dir_fd=number, follow_symlinks=False)
                if (observed.st_uid != self.uid or observed.st_dev != frame.directory.identity["device"]
                        or stat.S_IMODE(observed.st_mode) & 0o7022):
                    raise _RetainWork() from None
                if stat.S_ISDIR(observed.st_mode):
                    if frame.depth >= MAX_WORK_DEPTH:
                        raise _RetainWork() from None
                    child = self._directory_at(number, entry.name, frame.directory, cleanup=True)
                    iterator = self._new_iterator(child.slot.number, cleanup=True)
                    stack.append(_WorkFrame(child, iterator, frame.depth + 1))
                elif stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1:
                    child = self._file_at(number, entry.name, frame.directory, cleanup=True)
                    self._work_delete(child)
                else:
                    raise _RetainWork() from None
            self._namespace_metadata()
        except BaseException as error:
            primary = error
            self._remember(error)
        finally:
            for frame in reversed(stack):
                try:
                    frame.iterator.close()
                except BaseException as error:
                    self._remember(error)
                    if primary is None:
                        primary = error
        if isinstance(primary, (_RetainWork, OSError, BuildInputError)) and not self.guard.lifetime_ledger.fatal:
            self.operation.fail("work-retained")
            raise AndroidFileError("work-retained") from None
        if primary is not None:
            raise primary

    def close(self) -> None:
        self._owner()
        if self.close_claimed:
            return
        self.close_claimed = True
        self._require_consumers()
        if self.artifact is not None and (self.artifact._reader is not None or self.artifact._native):
            self._unknown(AndroidFileError("cleanup-unknown"))
        primary = None
        with self.guard.deferred(check_on_exit=False):
            iterator_count = len(self.iterators)
            for record in self.directories:
                if record.creation is not None:
                    try:
                        _check_creation(record.creation, record.identity)
                    except BaseException as error:
                        self._remember(error)
                        self._unknown_seen = True
                        self.guard._abort(error)
                        if primary is None:
                            primary = error
            for original in reversed(self.iterators):
                try:
                    original.close()
                except BaseException as error:
                    self._remember(error)
                    if primary is None:
                        primary = error
            for slot in reversed(self.slots):
                try:
                    self._close_slot(slot)
                except BaseException as error:
                    self._unknown_seen = True
                    self._remember(error)
                    if primary is None:
                        primary = error
            if self._namespace_owner is not None:
                try:
                    self._namespace_owner.cleanup()
                except BaseException as error:
                    self._unknown_seen = True
                    self._remember(error)
                    if primary is None:
                        primary = error
            # Namespace.check uses this same bounded names owner. Its late
            # iterator acquisition records also need their original settlement,
            # including a direct no-effect refusal before names entered its try.
            for index in range(iterator_count, len(self.iterators)):
                try:
                    self.iterators[index].close()
                except BaseException as error:
                    self._remember(error)
                    if primary is None:
                        primary = error
        self._close_complete = primary is None
        if primary is not None:
            raise primary

    def closed(self) -> bool:
        self._owner()
        return (self.close_claimed and self._close_complete and not self._unknown_seen
                and all(slot.number is None and slot.close_state == "CLOSED" for slot in self.slots)
                and all(iterator.close_state == "CLOSED" for iterator in self.iterators)
                and all(record.state in ("NEW", "NO_EFFECT", "DELETED") for record in self.deletions)
                and self.namespace is self._namespace_owner
                and (self._namespace_owner is None or self._namespace_owner.closed())
                and (self.artifact is None or self.artifact._reader is None and not self.artifact._native))

    def disposition(self) -> dict[str, str]:
        self._owner()

        def created(record: _DirectoryRecord | None, retained: str) -> str:
            if record is None or record.creation["state"] in ("NEW", "NO_EFFECT"):
                return "not-created"
            if (record.creation["state"] in ("ATTEMPTED", "UNKNOWN") or record.identity is None
                    or record.slot.close_state in ("ATTEMPTED", "UNKNOWN")):
                return "unknown"
            return "removed" if record.deleted else retained

        work = created(self._work, "retained-work")
        artifacts = created(self._artifacts, "retained-incomplete")
        if any(record.state in ("ATTEMPTED", "UNKNOWN")
               or record.original.slot.close_state in ("ATTEMPTED", "UNKNOWN")
               for record in self.deletions):
            work = "unknown"
        if self._snapshot is not None and (
                self._snapshot.slot.open_state in ("ATTEMPTED", "UNKNOWN")
                or self._snapshot.slot.close_state in ("ATTEMPTED", "UNKNOWN")):
            artifacts = "unknown"
        return {"work": work, "artifacts": artifacts}
