"""Original saved iOS build/recovery operation, with one finite inspection.

The operation owns the actual project invocation, saved-input descriptors,
exclusive retained output and native-tool bindings. Parsed paths, hashes and UI
receipts never replace these original owners. No Store or CLI runner exists.
"""
from __future__ import annotations

import errno
import hashlib
import os
import re
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ._desktop_ios_archive_control import IOSArchiveInput
from ._desktop_ios_archive_protocol import IOSArchiveRequest, REASONS, ROLES, SIGNED_ROLES, stages, require
from ._desktop_ios_archive_selection import (
    SavedIOSSelection, bind_saved_ios_version, select_saved_ios_configuration,
)
from .build_inputs import (
    InvocationCustody, _Directory, _FD, _StoreNamespace, _directory, _file, _name_key,
    _check_creation, _direct_refusal, _mkdir_private,
)
from .cancellation import DefaultCancellation
from .config import MAX_CONFIG_BYTES, MAX_VERSION_BYTES, ReleaseConfig
from .inspection import InspectionDeadline
from .owned_process import fatal_lifetime_error, run_owned

_OS_SCANDIR, _OS_UNLINK, _OS_RMDIR = os.scandir, os.unlink, os.rmdir
_SCAN_REFUSALS = {errno.ENOENT, errno.ENOTDIR, errno.EACCES, errno.EPERM, errno.EBADF, errno.EMFILE, errno.ENFILE}
_DELETE_REFUSALS = {errno.ENOENT, errno.ENOTDIR, errno.EACCES, errno.EPERM,
                    errno.EROFS, errno.ENOTEMPTY, errno.EEXIST, errno.EBUSY}
_READ = 64 * 1024
_MAX_SLOTS = 192
_MAX_WORK_ENTRIES = 100_000


class IOSArchiveError(Exception):
    def __init__(self, reason: str) -> None:
        require(reason in REASONS and reason != "none")
        self.reason = reason
        super().__init__("The original saved iOS archive operation could not complete")


def _directory_data(value: os.stat_result) -> dict:
    return {"device": str(value.st_dev), "inode": str(value.st_ino), "mode": value.st_mode,
            "uid": value.st_uid, "gid": value.st_gid}


def _tool_data(value: os.stat_result) -> dict:
    return {**_directory_data(value), "links": value.st_nlink, "size": value.st_size,
            "mtimeNs": str(value.st_mtime_ns), "ctimeNs": str(value.st_ctime_ns)}


@dataclass(eq=False)
class _Held:
    parent: int
    name: str
    slot: _FD
    directory: bool
    identity: dict | None = None
    creation: dict | None = None
    parent_record: _Held | None = None
    deleted: bool = False


@dataclass(eq=False)
class _Saved:
    held: _Held
    raw: bytes
    limit: int


@dataclass(eq=False)
class _IOSRemoval:
    """One original work-only consuming call, retained before its sole attempt."""

    files: _OriginalIOSFiles
    original: _Held
    state: str = "NEW"

    def remove(self) -> None:
        files, original = self.files, self.original
        files.operation.cleanup_checkpoint()
        files.require_work_consumers()
        require(self.state == "NEW")
        files.check_held(original)
        operation = os.rmdir if original.directory else os.unlink
        builtin = _OS_RMDIR if original.directory else _OS_UNLINK
        with files.guard.deferred(check_on_exit=False):
            self.state = "ATTEMPTED"
            try:
                result = operation(original.name, dir_fd=original.parent)
            except BaseException as error:
                self.state = "NO_EFFECT" if _direct_refusal(error, operation, builtin,
                    _IOSRemoval.remove.__code__, _DELETE_REFUSALS) else "UNKNOWN"
                files.operation.remember(error, fatal=self.state == "UNKNOWN")
                raise
            try:
                require(result is None and original.slot.number is not None)
                after = os.fstat(original.slot.number)
                identity = _directory(after) if original.directory else _file(after)
                ignored = set() if original.directory else {"ctime", "links"}
                require(after.st_nlink == 0 and all(identity[key] == original.identity[key]
                        for key in identity if key not in ignored))
                try:
                    os.stat(original.name, dir_fd=original.parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise IOSArchiveError("work-retained")
                original.deleted, self.state = True, "DELETED"
            except BaseException as error:
                self.state = "UNKNOWN"
                files.operation.remember(error, fatal=True)
                raise


class _IOSIterator:
    """A bounded original scandir, pre-reserved before its sole acquisition."""

    def __init__(self, files) -> None:
        self.files = files
        self.value = None
        self.state, self.close_state = "NEW", "NEW"

    def open(self, fd: int) -> None:
        operation = os.scandir
        self.state = "ATTEMPTED"
        try:
            with self.files.operation.guard.deferred(check_on_exit=False):
                self.value = operation(fd)
                require(self.value is not None and callable(getattr(type(self.value), "close", None))
                        and callable(getattr(type(self.value), "__next__", None)))
                self.state = "OPEN"
        except BaseException as error:
            self.state = "NO_EFFECT" if _direct_refusal(error, operation, _OS_SCANDIR,
                _IOSIterator.open.__code__, _SCAN_REFUSALS) else "UNKNOWN"
            self.files.operation.remember(error, fatal=self.state == "UNKNOWN")
            raise

    def close(self) -> None:
        if self.close_state == "CLOSED":
            return
        try:
            require(self.close_state == "NEW" and self.state not in {"ATTEMPTED", "UNKNOWN"})
            with self.files.operation.guard.deferred(check_on_exit=False):
                self.close_state = "ATTEMPTED"
                if self.value is not None:
                    require(self.value.close() is None)
                self.close_state = "CLOSED"
        except BaseException as error:
            self.close_state = "UNKNOWN"
            self.files.operation.remember(error, fatal=True)
            raise

    def __iter__(self):
        return self

    def __next__(self):
        self.files.point()
        require(self.state == "OPEN" and self.close_state == "NEW")
        self.files.operation.charge("iterator-advances", 1, 4_000_000)
        value = next(self.value)
        self.files.point()
        return value


class _OriginalIOSFiles:
    """No-follow finite selection and retained namespace, never deletion by path."""

    def __init__(self, operation) -> None:
        self.operation, self.guard = operation, operation.guard
        self.held: list[_Held] = []
        self.live: set[_Held] = set()
        self.directories: dict[str, _Held] = {}
        self.saved: dict[str, _Saved] = {}
        self.iterators: list[_IOSIterator] = []
        self.namespace: _StoreNamespace | None = None
        self.developer: _Directory | None = None
        self.sdk: _Directory | None = None
        self.xcodebuild: _Held | None = None
        self.system_tools: dict[str, _Held] = {}
        self.system_directory: _Directory | None = None
        self.tool_directories: list[_Held] = []
        self.work: _Held | None = None
        self.work_children: dict[str, _Held] = {}
        self.removals: list[_IOSRemoval] = []
        self.work_claimed = False
        self.close_claimed = self.close_complete = False

    def point(self) -> None:
        if self.operation.source.recovery and not self.operation.close_claimed:
            self.operation._tick()
        elif self.operation.close_claimed or self.guard.depth:
            self.operation.cleanup_checkpoint()
        else:
            self.operation._tick()

    def _known_number(self, number: int) -> None:
        """Borrow only a descriptor already rooted in this original operation."""
        require(type(number) is int and number >= 0)
        if any(original.slot.number == number for original in self.live):
            return
        if self.operation.signing is not None and self.operation.signing.known_descriptor(number):
            return
        invocation = self.operation.invocation
        project = None if invocation is None else invocation._original_project
        if (project is not None and project is invocation.project_owner
                and any(slot.number == number for slot in (*project.directory.slots, project.meta))):
            return
        if (self.namespace is not None and self.namespace.ios_operation is self.operation
                and any(slot.number == number for slot in self.namespace.slots)):
            return
        if any(directory is not None and any(slot.number == number for slot in directory.slots)
               for directory in (self.developer, self.sdk, self.system_directory)):
            return
        owner = self.operation.snapshot_binding.owner
        if owner is not None:
            from .ios_artifacts import _IOSSnapshotOwner
            require(type(owner) is _IOSSnapshotOwner and owner._desktop_binding is self.operation.snapshot_binding
                    and owner.cancellation is self.guard and owner._lane_binding is None)
            if (any(slot.number == number for slot in (owner.slot, *owner.parent.slots))
                    or any(lease is not None and lease.slot.number == number for lease in owner._leases)):
                return
        require(False)

    @contextmanager
    def entries(self, fd: int):
        self.point()
        self._known_number(fd)
        self.operation.charge("name-scans", 1, 65_536)
        iterator = _IOSIterator(self)
        self.iterators.append(iterator)
        primary = None
        try:
            iterator.open(fd)
            yield iterator
        except BaseException as error:
            primary = error
            self.operation.remember(error)
            raise
        finally:
            try:
                iterator.close()
            except BaseException:
                if primary is None:
                    raise
            if iterator.close_state == "CLOSED":
                self.iterators.remove(iterator)

    def names(self, fd: int, *, limit: int = 4096) -> set[str]:
        self.point()
        require(type(limit) is int and 0 < limit <= 4096)
        self._known_number(fd)
        before = os.fstat(fd)
        require(stat.S_ISDIR(before.st_mode))
        values, keys = set(), set()
        with self.entries(fd) as iterator:
            for entry in iterator:
                self.point()
                self.operation.charge("name-entries", 1, 2_000_000)
                name = entry.name
                require(type(name) is str and len(values) < limit)
                key = _name_key(name)
                if key in keys:
                    self.operation.fail("project-admission-refused")
                self.operation.charge("name-bytes", len(name.encode("utf-8")) + len(key.encode("utf-8")), 64 * 1024**2)
                values.add(name)
                keys.add(key)
            self.point()
            after = os.fstat(fd)
            require(_directory(before) == _directory(after)
                    and (before.st_mtime_ns, before.st_ctime_ns) == (after.st_mtime_ns, after.st_ctime_ns))
            return values

    def _reserve(self, parent: int, name: str, *, directory: bool, creation=None,
                 parent_record: _Held | None = None) -> _Held:
        self.point()
        self.operation.charge("original-file-slots", 1, _MAX_WORK_ENTRIES + 512)
        require(len(self.live) < _MAX_SLOTS)
        held = _Held(parent, name, _FD(self.guard), directory,
                     creation=creation, parent_record=parent_record)
        self.held.append(held)  # Original slot is rooted before open.
        self.live.add(held)
        return held

    def _open(self, held: _Held) -> _Held:
        require(held in self.live and held.identity is None)
        self._known_number(held.parent)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if held.directory else 0)
        number = held.slot.open(held.name, flags, dir_fd=held.parent)
        held.identity = _directory(os.fstat(number)) if held.directory else _file(os.fstat(number))
        self.check_held(held)
        return held

    def _hold(self, parent: int, name: str, *, directory: bool, parent_record=None) -> _Held:
        return self._open(self._reserve(parent, name, directory=directory, parent_record=parent_record))

    def close_held(self, held: _Held) -> None:
        held.slot.close()  # The original slot never retries an unknown close.
        require(held.slot.close_state == "CLOSED" and held.slot.number is None)
        self.live.discard(held)

    def check_held(self, held: _Held) -> None:
        self.point()
        require(held in self.live and not held.deleted and held.identity is not None and held.slot.number is not None)
        if held.parent_record is not None:
            require(held.parent_record.slot.number == held.parent)
            self.check_held(held.parent_record)
        project = _directory if held.directory else _file
        if (project(os.fstat(held.slot.number)) != held.identity
                or project(os.stat(held.name, dir_fd=held.parent, follow_symlinks=False)) != held.identity):
            self.operation.fail("artifact-changed" if self.operation._artifact is not None else "project-admission-refused")

    def _walk(self, relative: str) -> tuple[int, str]:
        self.point()
        path = PurePosixPath(relative)
        parts = relative.split("/")
        require(not path.is_absolute() and len(parts) <= 32 and len(relative.encode("utf-8")) <= 2048
                and all(part not in {"", ".", ".."} and len(part.encode("utf-8")) <= 255
                        and not any(ord(char) < 32 or ord(char) == 127 or char in "\\:" for char in part) for part in parts))
        parent, identity = self.operation.invocation._ios_archive_root(self.operation)
        require(identity == self.operation.request.native["rootIdentity"])
        for index, name in enumerate(parts[:-1]):
            prefix = "/".join(parts[:index + 1])
            names = self.names(parent)
            if name not in names:
                raise FileNotFoundError("saved iOS selection parent is absent")
            record = self.directories.get(prefix)
            if record is None:
                record = self._hold(parent, name, directory=True)
                self.directories[prefix] = record
            else:
                require(record.parent == parent and record.name == name)
                self.check_held(record)
            parent = record.slot.number
        names = self.names(parent)
        require(all(_name_key(name) != _name_key(parts[-1]) or name == parts[-1] for name in names))
        return parent, parts[-1]

    def _read(self, held: _Held, limit: int) -> bytes:
        self.check_held(held)
        require(not held.directory and held.identity["size"] <= limit and held.identity["links"] == 1)
        number = held.slot.number
        os.lseek(number, 0, os.SEEK_SET)
        blocks, size = [], 0
        while True:
            self.point()
            block = os.read(number, min(_READ, limit + 1 - size))
            require(type(block) is bytes)
            if not block:
                break
            size += len(block)
            require(size <= limit)
            self.operation.charge("input-read-bytes", len(block), 64 * 1024**2)
            blocks.append(block)
        self.check_held(held)
        require(size == held.identity["size"])
        return b"".join(blocks)

    def read_input(self, relative: str, *, limit: int) -> bytes | None:
        self.point()
        require(len(self.saved) < 3 or relative in self.saved)
        if relative in self.saved:
            original = self.saved[relative]
            require(original.limit == limit)
            if self._read(original.held, limit) != original.raw:
                self.operation.fail("saved-config-changed" if relative == "release/mobile-release.json" else "saved-version-changed")
            return original.raw
        try:
            parent, name = self._walk(relative)
            held = self._hold(parent, name, directory=False)
        except FileNotFoundError:
            return None
        raw = self._read(held, limit)
        self.saved[relative] = _Saved(held, raw, limit)
        return raw

    def check_inputs(self) -> None:
        for name, original in self.saved.items():
            self.point()
            if self._read(original.held, original.limit) != original.raw:
                self.operation.fail("saved-config-changed" if name == "release/mobile-release.json" else "saved-version-changed")
        for original in self.directories.values():
            self.check_held(original)

    def configured_container(self) -> Path:
        selected = self.operation.inputs.saved.configuration
        parent, name = self._walk(selected.container[1])
        record = self.directories.get(selected.container[1])
        if record is None:
            try:
                record = self._hold(parent, name, directory=True)
            except (FileNotFoundError, NotADirectoryError):
                self.operation.fail("container-missing")
            self.directories[selected.container[1]] = record
        self.check_held(record)
        return self.operation.root / selected.container[1]

    def acquire_namespace(self) -> None:
        self.point()
        require(self.namespace is None)
        self.namespace = _StoreNamespace(self.operation.root, self.guard, include_store=False,
            _descendants=("desktop-ios-archive", self.operation.operation_id), _exclusive_index=2,
            _ios_operation=self.operation)
        self.namespace.acquire()
        self.namespace.require_empty()
        self.work = self._reserve(self.namespace.fd, "work", directory=True, creation={"state": "NEW"})
        self._create_work(self.work)
        for name in ("home", "tmp", "DerivedData"):
            original = self._reserve(self.work.slot.number, name, directory=True,
                                     creation={"state": "NEW"}, parent_record=self.work)
            self.work_children[name] = original
            self._create_work(original)

    def _create_work(self, original: _Held) -> None:
        require(original.creation is not None and all(_name_key(name) != _name_key(original.name)
                for name in self.names(original.parent)))
        _mkdir_private(original.name, original.parent, self.guard, original.creation)
        self._open(original)
        require(original.identity["uid"] == os.geteuid() and original.identity["mode"] == 0o700
                and original.identity["device"] == os.fstat(original.parent).st_dev)
        os.fsync(original.parent)

    def work_path(self, role: str) -> Path:
        self.point()
        require(not self.work_claimed and role in self.work_children)
        self.namespace.check()
        self.check_held(self.work_children[role])
        return self.namespace.path / "work" / role

    def write_export_options(self, content: bytes) -> _Held:
        self.point()
        require(self.operation.signing is not None and type(content) is bytes and 0 < len(content) <= 16 * 1024
                and "ExportOptions.plist" not in self.work_children and self.work is not None)
        self.check_held(self.work)
        require(all(_name_key(name) != _name_key("ExportOptions.plist") for name in self.names(self.work.slot.number)))
        original = self._reserve(self.work.slot.number, "ExportOptions.plist", directory=False, parent_record=self.work)
        self.work_children["ExportOptions.plist"] = original
        number = original.slot.open(original.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, dir_fd=original.parent)
        original.identity = _file(os.fstat(number))
        self.check_held(original)
        offset = 0
        while offset < len(content):
            self.point()
            count = os.write(number, content[offset:])
            require(type(count) is int and 0 < count <= len(content) - offset)
            offset += count
        os.fsync(number)
        original.identity = _file(os.fstat(number))
        self.check_export_options(original, content)
        os.fsync(original.parent)
        return original

    def check_export_options(self, original: _Held, content: bytes) -> None:
        self.check_held(original)
        require(original is self.work_children.get("ExportOptions.plist") and not original.directory
                and original.identity["size"] == len(content)
                and os.pread(original.slot.number, len(content) + 1, 0) == content)
        self.check_held(original)

    def acquire_tools(self) -> None:
        self.point()
        require(self.developer is None and self.sdk is None and self.xcodebuild is None)
        if self.operation.source.recovery:
            require(self.system_directory is None and not self.system_tools)
            self.system_directory = _Directory(Path("/usr/bin"), self.guard, edit_checkpoints=True)
            self.system_directory.acquire()
            self.system_tools["security"] = self._hold(self.system_directory.fd, "security", directory=False)
            self.check_tools()
            return
        expected = self.operation.request.native["toolchain"]
        self.developer = _Directory(Path(expected["developerDir"]), self.guard, edit_checkpoints=True)
        self.developer.acquire()
        self.point()
        require(_directory_data(os.fstat(self.developer.fd)) == expected["developerIdentity"])
        # Every component is held; a symlinked SDK alias must first be resolved
        # by the fixed native selection, never followed by this core owner.
        self.sdk = _Directory(Path(expected["sdk"]), self.guard, edit_checkpoints=True)
        self.sdk.acquire()
        require(_directory_data(os.fstat(self.sdk.fd)) == expected["sdkIdentity"])
        parent = self.developer.fd
        for name in ("usr", "bin"):
            original = self._hold(parent, name, directory=True)
            self.tool_directories.append(original)
            parent = original.slot.number
        self.xcodebuild = self._hold(parent, "xcodebuild", directory=False)
        if self.operation.signing is not None:
            self.system_directory = _Directory(Path("/usr/bin"), self.guard, edit_checkpoints=True)
            self.system_directory.acquire()
            for name in ("security", "codesign", "openssl"):
                self.system_tools[name] = self._hold(self.system_directory.fd, name, directory=False)
        self.check_tools()

    def check_tools(self) -> None:
        self.point()
        if self.operation.source.recovery:
            require(self.developer is None and self.sdk is None and self.xcodebuild is None
                    and self.system_directory is not None and set(self.system_tools) == {"security"})
            self.system_directory.check()
            original = self.system_tools["security"]
            self.check_held(original)
            value = os.fstat(original.slot.number)
            require(_tool_data(value) == self.operation.request.native["security"]
                    and value.st_uid == 0 and value.st_mode & 0o022 == 0)
            return
        require(self.developer is not None and self.sdk is not None and self.xcodebuild is not None)
        self.developer.check()
        self.sdk.check()
        for original in self.tool_directories:
            self.check_held(original)
        self.check_held(self.xcodebuild)
        expected = self.operation.request.native["toolchain"]
        values = (os.fstat(self.developer.fd), os.fstat(self.sdk.fd), os.fstat(self.xcodebuild.slot.number))
        require(_directory_data(values[0]) == expected["developerIdentity"]
                and _directory_data(values[1]) == expected["sdkIdentity"]
                and _tool_data(values[2]) == expected["xcodebuildIdentity"])
        require(all(value.st_uid in {0, os.geteuid()} and value.st_mode & 0o022 == 0 for value in values))
        if self.operation.signing is not None:
            require(self.system_directory is not None and set(self.system_tools) == {"security", "codesign", "openssl"})
            self.system_directory.check()
            for name, original in self.system_tools.items():
                self.check_held(original)
                value = os.fstat(original.slot.number)
                require(_tool_data(value) == self.operation.request.native["signingTools"][name]
                        and value.st_uid == 0 and value.st_mode & 0o022 == 0)

    def require_work_consumers(self) -> None:
        operation = self.operation
        operation.owner()
        require(operation.commands_settled() and not self.iterators
                and (operation.signing is None or operation.signing.inputs_closed())
                and operation.snapshot_binding.dependents_settled_for(
                    owner=operation.snapshot_binding.owner, cancellation=self.guard))

    def _remove_work(self, original: _Held) -> None:
        self.operation.charge("work-removals", 1, _MAX_WORK_ENTRIES + 4)
        removal = _IOSRemoval(self, original)
        self.removals.append(removal)
        removal.remove()
        self.close_held(original)

    def finish_work(self) -> None:
        """Finite disposal of only this operation's exclusive build intermediates.

        No symlink, aliased entry, different-user/mount object or unknown
        consuming result is adopted. The archive is never in this traversal.
        Original independent descriptor closes still run if disposal refuses.
        """
        self.operation.owner()
        require(not self.work_claimed)
        self.work_claimed = True
        if self.work is None or self.work.creation["state"] in {"NEW", "NO_EFFECT"}:
            return
        self.require_work_consumers()
        self.operation.cleanup_checkpoint()
        self.namespace.check()
        self.check_held(self.work)

        def walk(original: _Held, depth: int) -> None:
            self.operation.cleanup_checkpoint()
            require(depth <= 32)
            self.check_held(original)
            before = os.fstat(original.slot.number)
            children, keys = [], set()
            # Close the complete bounded immediate inventory before any
            # consumption, so late case/NFC collisions cannot license removal.
            with self.entries(original.slot.number) as iterator:
                for entry in iterator:
                    self.operation.charge("work-entries", 1, _MAX_WORK_ENTRIES)
                    name = entry.name
                    require(type(name) is str and 0 < len(name.encode("utf-8")) <= 255
                            and name not in {".", ".."} and not any(char in name for char in "/\\\0"))
                    key = _name_key(name)
                    self.operation.charge("work-name-bytes", len(name.encode("utf-8")) + len(key.encode("utf-8")), 64 * 1024**2)
                    require(key not in keys)
                    keys.add(key)
                    observed = entry.stat(follow_symlinks=False)
                    require(observed.st_uid == os.geteuid() and observed.st_dev == original.identity["device"]
                            and stat.S_IMODE(observed.st_mode) & 0o7022 == 0
                            and (stat.S_ISDIR(observed.st_mode) or stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1))
                    self.operation.charge("work-bytes", observed.st_size if stat.S_ISREG(observed.st_mode) else 0, 8 * 1024**3)
                    children.append((name, observed))
            after = os.fstat(original.slot.number)
            require(_directory(before) == _directory(after)
                    and (before.st_mtime_ns, before.st_ctime_ns) == (after.st_mtime_ns, after.st_ctime_ns))
            for name, observed in children:
                self.operation.cleanup_checkpoint()
                self.check_held(original)
                directory = stat.S_ISDIR(observed.st_mode)
                child = self.work_children.get(name) if original is self.work else None
                if child is None:
                    child = self._hold(original.slot.number, name, directory=directory, parent_record=original)
                require(child.directory is directory and child.identity == (_directory(observed) if directory else _file(observed)))
                self.check_held(child)
                if directory:
                    walk(child, depth + 1)
                else:
                    self._remove_work(child)
            require(not self.names(original.slot.number))
            self._remove_work(original)

        try:
            with self.guard.deferred(check_on_exit=False):
                walk(self.work, 0)
                self.namespace.check()
        except BaseException as error:
            self.operation.remember(error)
            if not self.guard.lifetime_ledger.fatal:
                self.operation.fail("work-retained")
            raise
        finally:
            walk = None  # No finished recursive closure waits for collection.

    def work_disposition(self) -> str:
        original = self.work
        if original is None or original.creation["state"] in {"NEW", "NO_EFFECT"}:
            return "not-created"
        if (original.creation["state"] in {"ATTEMPTED", "UNKNOWN"} or original.identity is None
                or any(item.state in {"ATTEMPTED", "UNKNOWN"} for item in self.removals)
                or any(item.slot.open_state in {"ATTEMPTED", "UNKNOWN"}
                       or item.slot.close_state in {"ATTEMPTED", "UNKNOWN"} for item in self.held)):
            return "unknown"
        return "removed" if original.deleted else "retained-work"

    def close(self) -> None:
        self.operation.owner()
        if self.close_claimed:
            require(self.close_complete)
            return
        self.close_claimed = True
        first = None
        for held in self.held:
            if held.creation is not None:
                try:
                    _check_creation(held.creation, held.identity)
                except BaseException as error:
                    self.operation.remember(error, fatal=True)
                    if first is None:
                        first = error
        # Finite work disposal is separate; the archive and unknown output
        # stay retained. Every original close remains independent of disposal.
        actions = [iterator.close for iterator in reversed(self.iterators)]
        actions += [lambda held=held: self.close_held(held) for held in reversed(self.held) if held in self.live]
        if self.sdk is not None:
            actions.append(self.sdk.close)
        if self.developer is not None:
            actions.append(self.developer.close)
        if self.system_directory is not None:
            actions.append(self.system_directory.close)
        if self.namespace is not None:
            actions.append(self.namespace.cleanup)
        for action in actions:
            try:
                action()
            except BaseException as error:
                self.operation.remember(error, fatal=True)
                if first is None:
                    first = error
        self.close_complete = first is None and not self.live and all(held.slot.close_state == "CLOSED" for held in self.held) and all(
            iterator.close_state == "CLOSED" for iterator in self.iterators) and all(
            directory is None or all(slot.close_state == "CLOSED" for slot in directory.slots)
            for directory in (self.sdk, self.developer, self.system_directory)) and (self.namespace is None or self.namespace.closed()) and all(
            removal.state in {"NEW", "NO_EFFECT", "DELETED"} for removal in self.removals)
        if first is not None:
            raise first
        require(self.close_complete)

    def closed(self) -> bool:
        return self.close_claimed and self.close_complete


class _IOSInspectionDeadline:
    """One exact original operation + one clock at every existing inner check."""

    def __init__(self, operation, clock: InspectionDeadline) -> None:
        require(type(operation) is IOSArchiveOperation and type(clock) is InspectionDeadline)
        self.operation, self.clock, self.guard = operation, clock, operation.guard

    @property
    def expires_at(self) -> float:
        return min(self.clock.expires_at, self.operation.source.work_end)

    def check(self) -> None:
        operation = self.operation
        operation.owner()
        require(operation.inspection_deadline is self and self.guard is operation.guard)
        if self.guard.depth and (operation.close_claimed or operation.snapshot_binding.finish_claimed):
            operation.cleanup_checkpoint()
            require(operation.files is not None and not any(
                iterator.state in {"ATTEMPTED", "UNKNOWN"} or iterator.close_state in {"ATTEMPTED", "UNKNOWN"}
                for iterator in operation.files.iterators))
        else:
            operation._tick()
            require(operation.snapshot_binding.consumer_active)
        self.clock.check()  # Never renewed during copying/parsing/rechecks/disposal.

    def snapshot_owner(self):
        from .ios_artifacts import _IOSSnapshotOwner
        require(type(self) is _IOSInspectionDeadline)
        self.check()
        binding = self.operation.snapshot_binding
        require(type(binding.owner) is _IOSSnapshotOwner and binding.owner.deadline is self
                and binding.owner._desktop_binding is binding and binding.owner._lane_binding is None)
        binding.producer(binding.owner, self.guard)
        return binding.owner

    @contextmanager
    def descriptor(self, path: Path):
        """Fixed parser borrow from the original finite snapshot, not a reader API."""
        owner = self.snapshot_owner()
        parts = owner._parts(path)
        require(parts in owner.entries)
        entry = owner.entries[parts]
        require(entry["kind"] == "file" and entry["state"] == "READY" and entry["binding"] is not None)
        with owner.directory(path.parent) as parent:
            with owner.descriptor(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, parent=parent) as number:
                require(_file(os.fstat(number)) == entry["binding"]
                        and _file(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == entry["binding"])
                yield number
                self.check()
                require(_file(os.fstat(number)) == entry["binding"]
                        and _file(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == entry["binding"])
        self.check()


class IOSArchiveSnapshotBinding:
    """Private exact Desktop origin, not Store evidence or a callable hook."""

    def __init__(self, operation) -> None:
        require(type(operation) is IOSArchiveOperation)
        self.operation, self.guard = operation, operation.guard
        self.pid, self.thread = operation.pid, operation.thread
        self.owner = None
        self.consumer_active = self.consumer_entered = self.consumer_returned = False
        self.finish_claimed = self.finished = False

    def origin(self, owner, guard) -> None:
        self.operation.owner()
        require(self.pid == os.getpid() and self.thread is threading.current_thread()
                and self.operation.snapshot_binding is self and guard is self.guard
                and self.operation.guard is guard and owner is self.owner)

    def bind_owner(self, owner) -> None:
        from .ios_artifacts import _IOSSnapshotOwner
        self.origin(None, self.guard)
        require(type(owner) is _IOSSnapshotOwner and owner.cancellation is self.guard
                and owner._lane_binding is None and owner._desktop_binding is self
                and not self.finish_claimed and self.operation.inspection_deadline is owner.deadline)
        self.owner = owner

    def producer(self, owner, guard) -> None:
        self.origin(owner, guard)
        self.operation._tick()
        require(not self.finish_claimed and not self.finished and self.consumer_active
                and self.operation.commands_settled() and self.operation._returned.get("archive") == 0)

    @contextmanager
    def consumer(self):
        self.origin(self.owner, self.guard)
        require(not self.consumer_entered and not self.finish_claimed)
        self.consumer_entered, self.consumer_active = True, True
        try:
            yield
        except BaseException as error:
            self.operation.remember(error)
            raise
        finally:
            self.consumer_active = False
            self.consumer_returned = True

    def finish_consumers(self, *, cancellation, primary=None) -> None:
        self.origin(self.owner, cancellation)
        if primary is not None:
            self.operation.remember(primary)
        if self.finish_claimed:
            require(self.finished)
            return
        self.finish_claimed = True  # Retire admission before any checks/cleanup.
        require(not self.consumer_active and (not self.consumer_entered or self.consumer_returned)
                and self.operation.commands_settled()
                and (self.operation.files is None or not self.operation.files.iterators))
        if self.owner is not None:
            require(not self.owner._accounting_pending and not self.owner._accounting_failed
                    and self.owner._reserved == self.owner._retired
                    and all(lease is None for lease in self.owner._leases))
        self.finished = True

    def dependents_settled_for(self, *, owner, cancellation) -> bool:
        self.origin(owner, cancellation)
        return (self.finished and self.finish_claimed and not self.consumer_active
                and (not self.consumer_entered or self.consumer_returned) and self.operation.commands_settled()
                and (self.operation.files is None or not self.operation.files.iterators))


class OriginalIOSArchive:
    """Retained output descriptor; its path is diagnostic, not re-adoption."""

    def __init__(self, operation, original: _Held) -> None:
        require(type(operation) is IOSArchiveOperation and original.directory and operation._artifact is None)
        self.operation, self.original = operation, original
        self.inventory = None

    @property
    def path(self) -> Path:
        self.check()
        return self.operation.files.namespace.path / "archive.xcarchive"

    def check(self) -> None:
        operation = self.operation
        operation.checkpoint()
        require(operation._artifact is self and operation.files.namespace is not None)
        operation.files.namespace.check()
        operation.files.check_held(self.original)

    @contextmanager
    def root(self):
        self.check()
        require(self.operation.snapshot_binding.consumer_active)
        # Borrow the actual archive descriptor; no new pathname can replace it.
        yield self.original.slot.number
        self.check()


class OriginalIOSIPA:
    """Exact exported file beneath this operation's retained export directory."""

    def __init__(self, operation, directory: _Held, original: _Held) -> None:
        require(operation.signing is not None and directory.directory and not original.directory
                and original.parent_record is directory and operation._ipa is None)
        self.operation, self.directory, self.original = operation, directory, original
        self.inventory = None

    @property
    def path(self) -> Path:
        self.check()
        return self.operation.files.namespace.path / "export" / self.original.name

    def check(self) -> None:
        operation = self.operation
        operation.checkpoint()
        require(operation._ipa is self)
        operation.files.namespace.check()
        operation.files.check_held(self.original)

    @contextmanager
    def root(self):
        self.check()
        require(self.operation.snapshot_binding.consumer_active)
        os.lseek(self.original.slot.number, 0, os.SEEK_SET)
        yield self.original.slot.number
        self.check()


@dataclass(frozen=True, slots=True)
class BoundIOSInputs:
    config: ReleaseConfig
    saved: SavedIOSSelection


class IOSArchiveOperation:
    def __init__(self, request: IOSArchiveRequest, guard: DefaultCancellation, source: IOSArchiveInput) -> None:
        require(type(request) is IOSArchiveRequest and type(guard) is DefaultCancellation
                and type(source) is IOSArchiveInput and source.guard is guard
                and guard._ios_archive_source is source and source.active and source.request_returned
                and threading.current_thread() is threading.main_thread())
        self.request, self.guard, self.source = request, guard, source
        self.root, self.operation_id = Path(request.native["projectRoot"]), request.operation_id
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.invocation = None
        self.invocation_attempted = False
        self.inputs: BoundIOSInputs | None = None
        self.files: _OriginalIOSFiles | None = None
        self.snapshot_binding = IOSArchiveSnapshotBinding(self)
        self.inspection_deadline: _IOSInspectionDeadline | None = None
        self._artifact: OriginalIOSArchive | None = None
        self._ipa = None
        self.signing = None
        self.failure = None
        self.counters: dict[str, int] = {}
        self.roles = () if source.recovery else SIGNED_ROLES if source.signed else ROLES
        self._roles = {role: "new" for role in self.roles}
        self._command_slots = {role: None for role in self.roles}
        self._returned: dict[str, int] = {}
        self._pending = None
        self._command_before = 0
        self.stage = "accepted"
        self.prepared = self.close_claimed = self.resources_closed = False
        self.cleanup_errors: list[BaseException] = []
        self.tool_version: str | None = None
        source.bind_operation(self)  # Root before any child constructor/effect.
        if source.account_lifecycle:
            from ._desktop_ios_signed_operation import SignedIOSOperation
            self.signing = SignedIOSOperation(self)
        self.files = _OriginalIOSFiles(self)

    def owner(self) -> None:
        require(self.pid == os.getpid() and self.thread is threading.current_thread()
                and self.thread is threading.main_thread() and self.source.operation is self
                and self.source.guard is self.guard)
        self.guard._check_owner()

    def _tick(self) -> None:
        self.owner()
        require(not self.close_claimed)
        self.guard.check()
        if time.monotonic() >= self.source.work_end:
            self.source.stop("timed-out")
            self.guard.check()
        if self.failure is not None or self.source.first_failure is not None:
            raise IOSArchiveError(self.failure or "command-incomplete")

    def checkpoint(self) -> None:
        self._tick()
        require(self.invocation is not None)
        self.invocation.require(root=self.root, cancellation=self.guard,
            signing_lease=None if self.signing is None else self.invocation.signing_lease)
        if self.signing is not None and self.invocation.project_owner is not None:
            require(self.invocation.signing_lease is self.signing.lease)
        if self.invocation.project_owner is not None:
            _, identity = self.invocation._ios_archive_root(self)
            if identity != self.request.native["rootIdentity"]:
                self.fail("project-admission-refused")

    def cleanup_checkpoint(self) -> None:
        self.owner()
        endpoint = self.source.cleanup_endpoint()
        if time.monotonic() >= endpoint:
            self.fail("work-retained")

    def charge(self, name: str, amount: int, limit: int) -> None:
        if self.source.recovery and not self.close_claimed:
            self._tick()
        elif self.close_claimed or self.guard.depth:
            self.cleanup_checkpoint()
        else:
            self._tick()
        before = self.counters.get(name, 0)
        if type(amount) is not int or amount < 0 or before > limit - amount:
            self.fail("input-limit")
        self.counters[name] = before + amount

    def fail(self, reason: str) -> None:
        self.owner()
        if self.failure is None:
            self.failure = reason
        self.source.failure_observed()
        raise IOSArchiveError(reason)

    def remember(self, error: BaseException, *, fatal: bool = False) -> None:
        self.owner()
        self.source.failure_observed()
        self.guard.lifetime_ledger._remember(error)
        if fatal or fatal_lifetime_error(error, "Original iOS archive custody did not settle") is not None:
            self.guard._abort(error)

    def bind_invocation(self, invocation: InvocationCustody) -> None:
        self._tick()
        require(type(invocation) is InvocationCustody and self.invocation is None
                and invocation.root == self.root and invocation.mode == "build"
                and invocation.cancellation is self.guard and invocation.signing_lease is None)
        self.invocation = invocation

    def _namespace_root(self, namespace, *, ensure_meta: bool = False, cleanup: bool = False) -> int:
        self.owner()
        require(self.files is not None and self.files.namespace is namespace and self.invocation is not None
                and type(cleanup) is bool and not (cleanup and ensure_meta))
        fd, identity = (self.invocation._ios_archive_cleanup_root(self) if cleanup else self.invocation._ios_archive_root(self))
        require(identity == self.request.native["rootIdentity"])
        if ensure_meta:
            require(not self.close_claimed and self.invocation.project_owner is not None)
            self.invocation.project_owner.ensure_meta()
            fd, again = self.invocation._ios_archive_root(self)
            require(again == identity)
        return fd

    def bind_inputs(self) -> BoundIOSInputs:
        self.checkpoint()
        require(self.inputs is None and self.files is not None)
        raw = self.files.read_input("release/mobile-release.json", limit=MAX_CONFIG_BYTES)
        data, selected = select_saved_ios_configuration(raw, self.request.context["savedConfig"])
        version = self.files.read_input(selected.source, limit=MAX_VERSION_BYTES)
        saved = bind_saved_ios_version(selected, version, self.request.context["savedVersion"])
        self.inputs = BoundIOSInputs(ReleaseConfig(path=self.root / "release/mobile-release.json", root=self.root, data=data), saved)
        if not selected.prepare:
            self._roles["prepare"] = "not-configured"
        self.check_inputs()
        return self.inputs

    def check_inputs(self) -> None:
        self.checkpoint()
        require(self.files is not None)
        self.files.check_inputs()

    def _project_ignore_policy(self) -> bytes | None:
        self.checkpoint()
        return self.files.read_input(".gitignore", limit=256 * 1024)

    def prepare(self) -> None:
        self.checkpoint()
        require(self.inputs is not None and not self.prepared)
        self.files.acquire_namespace()
        self.files.acquire_tools()
        self.check_inputs()
        self.prepared = True

    def prepare_recovery(self) -> None:
        self.checkpoint()
        require(self.source.recovery and self.inputs is None and not self.prepared
                and self.files.namespace is None and self.files.work is None)
        self.files.acquire_tools()
        self.prepared = True

    def require(self, config: ReleaseConfig, cancellation) -> None:
        self.checkpoint()
        require(self.inputs is not None and self.inputs.config is config and cancellation is self.guard
                and self.prepared and self.guard._ios_archive_source is self.source)

    def selection(self) -> dict | None:
        if self.inputs is None:
            return None
        value = self.inputs.saved.configuration
        return {"containerKind": value.container[0], "container": value.container[1], "scheme": value.scheme,
                "configuration": value.configuration, "bundleId": value.bundle_id,
                "symbolsPolicy": value.symbols_policy, "preparationConfigured": bool(value.prepare)}

    def advance(self, stage: str) -> None:
        self.checkpoint()
        order = stages(self.request.context)
        require(stage in order and (self.stage == "accepted" or order.index(stage) > order.index(self.stage)))
        self.stage = stage
        self.source.progress(stage)

    def commands_settled(self) -> bool:
        self.owner()
        facts = self.guard.lifetime_ledger.verdict()
        return (facts.cleanup_complete and facts.contained and (facts.profile_calls == 0 if self.signing is None else self.signing.commands_settled()) and self._pending is None
                and all(state in {"new", "not-configured", "no-call"}
                        or state not in {"armed", "calling", "attempted"} and self._command_outcome(role) is not None
                        for role, state in self._roles.items()))

    def bind_command_slot(self, engine, slot) -> None:
        """Root only the original pending role's slot; never poll or dispatch."""
        from ._command_process import CommandOutcomeSlot, _Outer
        self.owner()
        if self.signing is not None:
            self.signing.bind_command_slot(engine, slot)
            return
        role = self._pending
        require(type(engine) is _Outer and type(slot) is CommandOutcomeSlot
                and engine.guard is self.guard and engine.owns is False
                and engine.scope is None and engine.binding is None and engine._store_timing is None
                and engine.slot is slot and slot._engine is engine and slot._scope is None
                and slot._nonce == engine.nonce and slot.read() is None
                and self.guard._ios_archive_source is self.source and self.source.require_operation() is self
                and self.guard.lifetime_ledger._command is slot
                and role in ROLES and self._roles[role] == "attempted" and self._command_slots[role] is None)
        self._command_slots[role] = slot

    def _command_outcome(self, role: str):
        """Read original closed finality, not exception/aggregate-count guesses."""
        from ._command_process import (
            CommandOutcomeSlot, NoTargetProof, OriginalCommandFinality, OriginalCommandOutcome, RouteHistory, _Outer,
        )
        self.owner()
        if self.signing is not None:
            return self.signing.outcome(role)
        slot = self._command_slots[role]
        if type(slot) is not CommandOutcomeSlot:
            return None
        engine = slot._engine
        if (type(engine) is not _Outer or engine.guard is not self.guard or engine.slot is not slot
                or engine.scope is not None or engine.binding is not None or engine.owns is not False
                or slot._scope is not None or slot._nonce != engine.nonce or getattr(engine, "phase", None) != "CLOSED"
                or engine.evidence is not None):
            return None
        outcome = slot.read()
        if (type(outcome) is not OriginalCommandOutcome or outcome._engine is not engine or outcome.nonce != slot._nonce
                or type(outcome.original_finality) is not OriginalCommandFinality
                or outcome.original_finality._engine is not engine
                or type(outcome.create_w) is not RouteHistory or type(outcome.run_tool) is not RouteHistory
                or outcome.create_w.retired is not True or outcome.run_tool.retired is not True):
            return None
        if outcome.no_target is not None:
            if (type(outcome.no_target) is not NoTargetProof or outcome.no_target._engine is not engine
                    or outcome.no_target.kind not in {"NO_W_CREATION", "CLOSED_BEFORE_RUN", "EXEC_REJECTED"}
                    or outcome.result_integrity != "complete"):
                return None
        elif outcome.create_w.attempted is not True or outcome.run_tool.attempted is not True:
            return None
        return outcome

    def _observe_command(self, role: str) -> None:
        self.owner()
        observed = self._command_outcome(role)
        if observed is not None and observed.no_target is not None:
            self._roles[role] = "no-target"
        elif (observed is not None and observed.result_integrity == "complete" and observed.termination == "normal-exit"
              and type(observed.returncode) is int and 0 <= observed.returncode <= 255):
            self._returned[role] = observed.returncode
            self._roles[role] = "returned"
        else:
            self._roles[role] = "unknown"
        self._pending = None

    def command_dispatch(self):
        self.owner()
        dispatched = self.guard.lifetime_ledger.verdict().command_dispatched
        if dispatched is not True and self.signing is not None and not self.signing.commands_settled():
            return None
        # A prior positive attempt stays positive, but absent finality never
        # becomes known no-effect merely because no ledger slot was published.
        if dispatched is not True and any(state not in {"new", "not-configured", "no-call"}
                and self._command_outcome(role) is None for role, state in self._roles.items()):
            return None
        return dispatched

    def _arm(self, role: str) -> None:
        self.checkpoint()
        require(role in self.roles and self._roles[role] == "new" and self.commands_settled())
        prior = self.roles[:self.roles.index(role)]
        require(all(self._roles[name] == "not-configured" or self._returned.get(name) == 0 for name in prior))
        self._command_before = self.guard.lifetime_ledger.verdict().commands
        self._roles[role], self._pending = "armed", role

    def command_environment(self) -> dict[str, str]:
        self.checkpoint()
        require(self.prepared)
        tool = self.request.native["toolchain"]
        value = {"PATH": tool["developerDir"] + "/usr/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                "DEVELOPER_DIR": tool["developerDir"], "SDKROOT": tool["sdk"],
                "HOME": str(self.files.work_path("home")), "TMPDIR": str(self.files.work_path("tmp")),
                "CFFIXED_USER_HOME": str(self.files.work_path("home")),
                "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "CI": "true",
                "MOBILE_RELEASE_DEFER_EXTERNAL_UPLOADS": "1",
                "MOBILE_RELEASE_VERSION_NAME": self.inputs.saved.release.name,
                "MOBILE_RELEASE_BUILD_NUMBER": str(self.inputs.saved.release.build)}
        return value if self.signing is None else self.signing.main_environment(value)

    def command_limits(self, timeout: int, capture: bool, output_limit: int) -> tuple[int, int]:
        self.checkpoint()
        role = self._pending
        require(role in ROLES and self._roles[role] == "calling" and type(capture) is bool
                and capture is (role in {"xcode-version", "ios-sdk"}) and type(timeout) is int and timeout > 0
                and type(output_limit) is int and output_limit > 0)
        self._roles[role] = "attempted"
        return min(timeout, {"xcode-version": 30, "ios-sdk": 30, "prepare": 600, "archive": 3600}[role]), min(output_limit, 2 * 1024**2)

    def _run(self, role: str, argv: tuple[str, ...]):
        self.check_inputs()
        self.files.check_tools()
        self._arm(role)
        try:
            runner = run_owned
            arguments = {"cwd": self.root, "environ": self.command_environment(),
                "capture": role in {"xcode-version", "ios-sdk"},
                "timeout": {"xcode-version": 30, "ios-sdk": 30, "prepare": 600, "archive": 3600, "export": 1800}[role],
                "output_limit": 2 * 1024**2, "cancellation": self.guard}
            self._roles[role] = "calling"
            if self.signing is not None and role in {"prepare", "archive", "export"}:
                session = self.signing.session
                require(session is not None and self.signing.lease.active is session)
                result = session.run(list(argv), kind="build", cwd=self.root, capture=arguments["capture"],
                    timeout=arguments["timeout"], environ=arguments["environ"])
            else:
                result = runner(argv, **arguments)
            # Actual return is retained before any later STOP/drift check.
            self.owner()
            self._observe_command(role)
            facts = self.guard.lifetime_ledger.verdict()
            require(self._roles[role] == "returned" and self._returned[role] == result.returncode
                    and facts.cleanup_complete and facts.contained and facts.command_dispatched is True
                    and (self.signing is not None or facts.profile_calls == 0) and facts.commands == self._command_before + 1)
        except BaseException as error:
            self.remember(error)
            if self._roles[role] == "armed":
                self._roles[role], self._pending = "no-call", None
            else:
                self._observe_command(role)
            raise
        if result.returncode != 0:
            self.fail("command-failed")
        self.files.check_tools()
        self.check_inputs()
        return result

    def check_xcode(self) -> None:
        self.require(self.inputs.config, self.guard)
        program = self.request.native["toolchain"]["developerDir"] + "/usr/bin/xcodebuild"
        version = self._run("xcode-version", (program, "-version")).stdout
        if type(version) is not str or re.fullmatch(r"Xcode [0-9]+(?:\.[0-9]+){0,2}\nBuild version [0-9A-Za-z]+\s*", version) is None:
            self.fail("toolchain-mismatch")
        sdk = self._run("ios-sdk", (program, "-version", "-sdk", "iphoneos", "Path")).stdout
        if type(sdk) is not str or sdk.strip() != self.request.native["toolchain"]["sdk"]:
            self.fail("toolchain-mismatch")
        self.tool_version = version.strip()

    def run_preparation(self) -> None:
        self.require(self.inputs.config, self.guard)
        value = self.inputs.saved.configuration.prepare
        require(bool(value))
        self._run("prepare", value)

    def run_archive(self, argv: list[str]) -> None:
        from .ios import _archive_command, _signing_archive_settings
        self.require(self.inputs.config, self.guard)
        selected = self.inputs.saved.configuration
        expected = _archive_command(selected.container, self.files.configured_container(), selected.scheme,
            selected.configuration, self.files.namespace.path / "archive.xcarchive", self.inputs.saved.release,
            program=self.request.native["toolchain"]["developerDir"] + "/usr/bin/xcodebuild",
            derived_data=self.files.work_path("DerivedData"))
        expected += (_signing_archive_settings(self.inputs.config.section("ios")["teamId"], self.signing.profile_specifier)
                     if self.signing is not None else ["CODE_SIGNING_ALLOWED=NO", "CODE_SIGNING_REQUIRED=NO"])
        require(argv == expected)
        require(all(_name_key(name) != "archive.xcarchive" for name in self.files.names(self.files.namespace.fd)))
        self._run("archive", tuple(argv))

    def run_export(self) -> None:
        import plistlib
        from .ios import _export_options
        self.require(self.inputs.config, self.guard)
        require(self.signing is not None and self.signing.phase == "building" and self._ipa is None)
        self.artifact().check()
        require(self.files.names(self.files.namespace.fd) == {"work", "archive.xcarchive"})
        ios = self.inputs.config.section("ios")
        content = plistlib.dumps(_export_options(ios["bundleId"], ios["teamId"], self.signing.profile_specifier), sort_keys=True)
        options = self.files.write_export_options(content)
        self.files.check_export_options(options, content)
        self._run("export", (self.request.native["toolchain"]["developerDir"] + "/usr/bin/xcodebuild", "-exportArchive",
            "-archivePath", str(self.artifact().path), "-exportPath", str(self.files.namespace.path / "export"),
            "-exportOptionsPlist", str(self.files.work_path("ExportOptions.plist"))))
        self.files.check_export_options(options, content)
        require(self.commands_settled() and self._returned.get("export") == 0
                and self.files.names(self.files.namespace.fd) == {"work", "archive.xcarchive", "export"})
        directory = self.files._hold(self.files.namespace.fd, "export", directory=True)
        names = self.files.names(directory.slot.number, limit=128)
        candidates = [name for name in names if name.endswith(".ipa")]
        if len(candidates) != 1:
            self.fail("artifact-missing")
        name = candidates[0]
        require(0 < len(name.encode("utf-8")) <= 255 and not any(ord(char) < 32 or ord(char) == 127 or char in "/\\:" for char in name))
        original = self.files._hold(directory.slot.number, name, directory=False, parent_record=directory)
        require(0 < original.identity["size"] <= 4 * 1024**3)
        self._ipa = OriginalIOSIPA(self, directory, original)
        self._ipa.check()

    def ipa(self) -> OriginalIOSIPA:
        self.checkpoint()
        require(type(self._ipa) is OriginalIOSIPA and self.signing is not None)
        self._ipa.check()
        return self._ipa

    def capture_after(self) -> OriginalIOSArchive:
        self.checkpoint()
        require(self._artifact is None and self._returned.get("archive") == 0 and self.commands_settled())
        self.files.namespace.check()
        require(self.files.names(self.files.namespace.fd) == {"work", "archive.xcarchive"})
        try:
            original = self.files._hold(self.files.namespace.fd, "archive.xcarchive", directory=True)
        except (FileNotFoundError, NotADirectoryError):
            self.fail("artifact-missing")
        self._artifact = OriginalIOSArchive(self, original)
        self._artifact.check()
        return self._artifact

    def artifact(self) -> OriginalIOSArchive:
        self.checkpoint()
        require(type(self._artifact) is OriginalIOSArchive)
        self._artifact.check()
        return self._artifact

    def begin_inspection(self, artifacts, cancellation):
        self.checkpoint()
        require(cancellation is self.guard and self.inspection_deadline is None
                and self.snapshot_binding.owner is None and not self.snapshot_binding.finish_claimed
                and self.commands_settled() and self._returned.get("archive") == 0)
        expected = {"ios-archive": self.artifact().path}
        if self.signing is not None:
            require(self.signing.phase == "inspecting" and self.signing.inputs_closed()
                    and self.signing.session is not None and self.signing.session.closed
                    and self._returned.get("export") == 0)
            expected["ios-ipa"] = self.ipa().path
        require(type(artifacts) is dict and artifacts == expected)
        self.inspection_deadline = _IOSInspectionDeadline(self, InspectionDeadline())
        return self.inspection_deadline

    def inspection_observed(self, snapshot) -> None:
        from .ios_artifacts import IOSArtifactSnapshot
        self.checkpoint()
        binding = self.snapshot_binding
        require(type(snapshot) is IOSArtifactSnapshot and snapshot._owner is binding.owner
                and snapshot.deadline is self.inspection_deadline and snapshot.cancellation is self.guard
                and binding.consumer_active and self.artifact().inventory is None
                and set(snapshot.bindings) == ({"ios-archive"} if self.signing is None else {"ios-archive", "ios-ipa"})
                and type(snapshot.bindings["ios-archive"]) is dict)
        self._artifact.inventory = snapshot.bindings["ios-archive"]
        if self.signing is not None:
            self._ipa.inventory = snapshot.bindings["ios-ipa"]

    def snapshot_closed(self) -> bool:
        binding = self.snapshot_binding
        return (binding.finished and binding.finish_claimed and (binding.owner is None
                or binding.owner._desktop_closed_for(binding, self.guard)))

    def close(self) -> None:
        self.owner()
        if self.close_claimed:
            require(self.resources_closed)
            return
        self.close_claimed = True
        first = None
        binding = self.snapshot_binding
        actions = []
        if not binding.finish_claimed:
            actions.append(lambda: binding.finish_consumers(cancellation=self.guard))
        if binding.owner is not None and not binding.owner.claimed:
            actions.append(binding.owner.cleanup)
        if self.files is not None:
            if not self.files.work_claimed:
                actions.append(self.files.finish_work)
            actions.append(self.files.close)
        with self.guard.deferred(check_on_exit=False):
            for action in actions:
                try:
                    action()
                except BaseException as error:
                    # A bounded, known work-retention refusal is not an
                    # unknown descriptor close. Original closes still decide
                    # finality; the retained work separately prevents success.
                    self.remember(error, fatal=not (isinstance(error, IOSArchiveError)
                                                   and error.reason == "work-retained"))
                    self.cleanup_errors.append(error)
                    if first is None:
                        first = error
        self.resources_closed = self.snapshot_closed() and (self.files is None or self.files.closed())
        if first is not None:
            raise first
        require(self.resources_closed)

    def closed(self) -> bool:
        self.owner()
        invocation_closed = (not self.invocation_attempted if self.invocation is None else self.invocation._ios_archive_closed(self))
        return self.close_claimed and self.resources_closed and invocation_closed

    def command_outcomes(self) -> dict:
        return {role: ({"outcome": "exited", "exitCode": self._returned[role]} if role in self._returned else
                       {"outcome": "not-configured" if self._roles[role] == "not-configured" else
                                   "not-dispatched" if self._roles[role] in {"new", "no-call", "no-target"} else "unknown", "exitCode": None})
                for role in self.roles}

    def disposition(self) -> dict:
        binding, namespace = self.snapshot_binding, None if self.files is None else self.files.namespace
        snapshot = ("not-created" if binding.owner is None or binding.owner.creation["state"] in {"NEW", "NO_EFFECT"}
                    else "removed" if binding.owner._desktop_closed_for(binding, self.guard) else "unknown")
        output = "not-created"
        if namespace is not None:
            state = namespace.creations[-1]["state"]
            output = ("retained-incomplete" if state == "CREATED" and namespace.identities[-1] is not None
                      else "not-created" if state in {"NEW", "NO_EFFECT"} else "unknown")
        return {"snapshot": snapshot, "work": "not-created" if self.files is None else self.files.work_disposition(),
                "output": output, "relativeDirectory": None if output == "not-created"
                else f".mobile-release/desktop-ios-archive/{self.operation_id}"}
