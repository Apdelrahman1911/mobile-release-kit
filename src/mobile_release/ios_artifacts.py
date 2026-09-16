"""Read-only correspondence of a private iOS artifact snapshot.

No application code runs here. These structural/content checks complement (not
replace) native signing validation and authenticated whole-artifact provenance.
"""
from __future__ import annotations

import hashlib
import io
import os
import stat
import struct
import sys
import tempfile
import threading
import unicodedata
import zipfile
import zlib
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Mapping

from .config import ReleaseVersion
from .errors import ValidationError
from .inspection import InspectionDeadline
from .ios_entitlements import load_plist_dictionary, typed_value
from .macho import MACHO_MAGICS, MachOSlice, inspect_macho
from ._profile_callers import fatal_cancellation_error, first_primary_context
from .build_inputs import (
    FiniteScratch, _FD, _check_creation, _consumer_idle, _directory,
    _file, _mkdir_private,
)
from .cancellation import CleanupScope

MAX_FILES = 100_000
MAX_SNAPSHOT_ENTRIES = 6 * MAX_FILES + 16  # Three originals plus their bounded unpacked views.
MAX_DEPTH = 64
MAX_SNAPSHOT_FDS = 2 * (MAX_DEPTH + 3) + 8
MAX_FILE_BYTES = 4 * 1024**3
MAX_TOTAL_BYTES = 16 * 1024**3
MAX_ZIP_DIRECTORY = 32 * 1024**2
MAX_PLIST_BYTES = 4 * 1024**2
CHUNK = 1024**2
IOS_ARTIFACT_NAMES = frozenset({"ios-ipa", "ios-archive", "ios-dsyms"})


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(f"iOS artifact correspondence: {message}")


def _parts(value: str) -> tuple[str, ...]:
    parts = tuple(value.split("/"))
    try:
        encoded_length = len(value.encode("utf-8"))
    except UnicodeError as error:
        raise ValidationError("iOS artifact path is not valid Unicode") from error
    _require(bool(value) and encoded_length <= 2048 and len(parts) <= MAX_DEPTH,
             "path length/depth exceeds its bound")
    _require(all(part not in {"", ".", ".."} and len(part.encode("utf-8")) <= 255 and
                 not part.endswith((" ", ".")) and not any(ord(c) < 32 or ord(c) == 127 or c in "\\:" for c in part)
                 for part in parts), "unsafe path component")
    return parts


class _Paths:
    def __init__(self) -> None:
        self.paths: dict[str, tuple[str, bool]] = {}

    def add(self, name: str, directory: bool) -> None:
        parts = _parts(name)
        for index in range(1, len(parts) + 1):
            path = "/".join(parts[:index])
            is_directory = directory or index < len(parts)
            key = unicodedata.normalize("NFC", path).casefold()
            previous = self.paths.get(key)
            _require(previous is None or previous == (path, is_directory),
                     "case/Unicode collision or file/directory conflict")
            self.paths[key] = (path, is_directory)
        _require(len(self.paths) <= MAX_FILES, "file/directory count exceeds its bound")


class _Budget:
    def __init__(self, deadline: InspectionDeadline) -> None:
        self.deadline, self.count, self.size = deadline, 0, 0

    def tick(self, size: int = 0, *, entry: bool = False) -> None:
        self.deadline.check()
        self.size += size
        self.count += int(entry)
        _require(self.count <= MAX_FILES and self.size <= MAX_TOTAL_BYTES,
                 "inspection exceeds its count/size bound")


@dataclass(frozen=True)
class _File:
    size: int
    sha256: str
    magic: bytes


Inventory = dict[str, _File | None]


def _attributes(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _revision(value: os.stat_result) -> tuple[int, int, int]:
    return value.st_mtime_ns, value.st_ctime_ns, value.st_nlink


class _SnapshotFailures:
    """One original primary; diagnostics never prevent the next fixed close."""

    def __init__(self, guard) -> None:
        self.guard = guard
        self.first: BaseException | None = None
        self.diagnostic_failed = False

    def remember(self, error: BaseException, *, abort: bool = True) -> None:
        if self.first is None:
            self.first = error
        if self.guard.pid == os.getpid():
            try:
                if abort:
                    self.guard._abort(error)
                else:
                    self.guard.lifetime_ledger._remember(error)
            except BaseException:
                self.diagnostic_failed = True

    def attempt(self, action, *args) -> None:
        try:
            action(*args)
        except BaseException as error:
            self.remember(error)

    def raise_first(self) -> None:
        if self.first is not None:
            raise self.first
        _require(not self.diagnostic_failed, "snapshot cleanup diagnostics are unconfirmed")


class _SnapshotClose:
    """Acyclic original close-return record, not a lease/scope backreference."""

    def __init__(self, slot: _FD) -> None:
        self.slot = slot
        self.attempted = self.returned = False

    def close(self) -> None:
        if self.attempted:
            _require(self.returned, "snapshot original close callback is unconfirmed")
            return
        self.attempted = True
        self.slot.close()
        self.returned = True


class _SnapshotLease:
    """One strongly owned original; no reference back to its containing pool."""

    def __init__(self, guard, index: int) -> None:
        self.index = index
        self.slot = _FD(guard)
        self.close = _SnapshotClose(self.slot)
        self.scope = CleanupScope(guard, self.close.close, owns_cancellation=False,
            fork_cleanup=self.slot.after_fork_child, first_primary=True)
        self.failures = _SnapshotFailures(guard)
        self.scope_returned = self.scope_failed = False


def _snapshot_no_cleanup() -> None:
    pass


class _SnapshotScope(CleanupScope):
    """Fixed Store finish -> snapshot cleanup entry, prearmed before acquire.

    In particular there is no post-claim allocation of the generic _scope's
    [finish, owner.cleanup] action list. Failure before/inside finish cannot
    bypass the original owner's independent closes.
    """

    def __init__(self, owner) -> None:
        self.owner = owner
        self.failures = _SnapshotFailures(owner.cancellation)
        self.finish = owner._lane_binding._record.finish
        self.owner_cleanup = owner.cleanup
        super().__init__(owner.cancellation, self._close_owner,
            owns_cancellation=False, fork_cleanup=owner.fork_close, first_primary=True)

    def _close_owner(self) -> None:
        try:
            try:
                self.finish(cancellation=self.cancellation, primary=self._first_error)
            except BaseException as error:
                self.failures.remember(error)
        finally:
            try:
                self.owner_cleanup()
            except BaseException as error:
                self.failures.remember(error)
        self.failures.raise_first()

    def _exit_owned(self, exception_type, error, traceback) -> bool:
        # The original base __exit__ frame has already checked PID/thread and
        # still defers its owned signals if constructing/entering deferred()
        # fails. Cover that dispatch BEFORE it can claim the outer scope.
        try:
            try:
                if not self.claimed:
                    self._first_error = error
                result = super()._exit_owned(exception_type, error, traceback)
            finally:
                # Only the original owner claim means its cleanup was entered.
                # An outer scope claim alone cannot skip this prearmed callback.
                # Owner/FD state machines retain UNKNOWN; no number is retried.
                if self.owner is not None and not self.owner.claimed:
                    try:
                        self.cleanup()
                    except BaseException as cleanup_error:
                        self._record_failure(cleanup_error)
        except BaseException as late_error:
            primary = self._first_error if self._first_error is not None else error
            raise (primary if primary is not None else late_error) from None
        if self._first_error is not None and self._first_error is not error:
            raise self._first_error from None
        return result

    def release_healthy_callbacks(self) -> None:
        # No healthy retired self->bound-method->self cycle waits for GC.
        # Failed originals remain diagnostic debt, never a delayed retry.
        if self.claimed and self._first_error is None and not self._cleanup_errors:
            self.cleanup = _snapshot_no_cleanup
            self.fork_cleanup = None
            self.finish = self.owner_cleanup = None
            self.owner = None


@contextmanager
def _snapshot_scope(owner):
    guard = owner.cancellation
    scope = _SnapshotScope(owner)
    try:
        try:
            try:
                with scope:
                    owner.acquire()
                    guard.check()
                    try:
                        yield owner
                    except BaseException as error:
                        if guard.pid == os.getpid():
                            try:
                                guard.lifetime_ledger._remember(error)
                            except BaseException as diagnostic:
                                scope.failures.remember(diagnostic)
                        raise
            finally:
                scope.__exit__(*sys.exc_info())
            _require(guard.pid == os.getpid(), "inherited snapshot cannot publish parent completion")
            guard.check()
        except BaseException as error:
            primary = scope._first_error if scope._first_error is not None else error
            if guard.pid == os.getpid():
                fatal = fatal_cancellation_error(primary, guard, "snapshot lifetime did not settle")
                if fatal is not None:
                    raise fatal from None
            raise primary
    finally:
        scope.release_healthy_callbacks()


class _LaneSnapshotOwner(FiniteScratch):
    """Bounded original-created snapshot entries under one exact Store binding."""

    def __init__(self, guard, record, *, deadline: InspectionDeadline) -> None:
        super().__init__("ios-snapshot", guard, None, lane_evidence=record)
        self.deadline = deadline
        self.entries: dict[tuple[str, ...], dict[str, Any]] = {}
        self.root_entry = self._entry("directory")
        self._leases: list[_SnapshotLease | None] = [None] * MAX_SNAPSHOT_FDS
        self._reserved = self._retired = self._peak = 0
        self._accounting_pending = self._accounting_failed = False
        self._walks_closed = False
        self._audit_epoch = 0
        self._cleanup_failures = _SnapshotFailures(guard)
        self._fork_failures = _SnapshotFailures(guard)
        # Fixed callbacks exist before acquire; cleanup creates no action list.
        self._dispose_callback = self._dispose
        self._registry_close_callback = self._close_registry
        self._root_close_callback = self.slot.close
        self._parents_close_callback = self._close_parents

    @staticmethod
    def _entry(kind: str, parts: tuple[str, ...] = ()) -> dict[str, Any]:
        return {"kind": kind, "parts": parts, "state": "RESERVED", "binding": None,
                "creation": {"state": "NEW"}, "children": {}, "revision": None,
                "seen": 0, "conflict": 0, "complete": 0, "cleanup_revision": None,
                "foreign": True}

    def acquire(self) -> None:
        super().acquire()
        self.root_entry["binding"] = self.identity
        self.root_entry["revision"] = _revision(os.fstat(self.slot.number))
        self.root_entry["state"] = "READY"

    def _parts(self, path: Path) -> tuple[str, ...]:
        try:
            relative = path.relative_to(self._path)
        except ValueError:
            raise ValidationError("iOS snapshot output is outside its original private root") from None
        if relative == Path("."):
            return ()
        parts = tuple(relative.parts)
        _require(len(parts) <= MAX_DEPTH + 3 and len(relative.as_posix().encode("utf-8")) <= 4096,
                 "snapshot private path exceeds its fixed envelope")
        for part in parts:
            _parts(part)
        return parts

    def _producer(self) -> None:
        self._owner()
        record = self._lane_binding._record
        record._origin(self.cancellation)
        _require(not record._sealed and not record._attempted and not record._finished,
                 "snapshot publication is closed before Store dispatch")

    def _step(self, *, cleanup: bool = False) -> None:
        self._owner(cleanup=cleanup)
        if cleanup and not self.cancellation.depth:
            self.cancellation.check()
        _require(not self._walks_closed, "snapshot inspection authorization is closed")
        try:
            self.deadline.check()
        except BaseException:
            self._walks_closed = True
            raise

    def _pool_check(self) -> int:
        self._owner(cleanup=True)
        try:
            _require(not self._accounting_pending and not self._accounting_failed,
                     "snapshot original descriptor accounting is unconfirmed")
            occupied = sum(lease is not None for lease in self._leases)
            _require(len(self._leases) == MAX_SNAPSHOT_FDS and self._reserved == self._retired + occupied,
                     "snapshot original descriptor conservation differs")
            return occupied
        except BaseException as error:
            self._accounting_failed = True
            self._cleanup_failures.remember(error)
            raise

    def _reserve_lease(self, *, cleanup: bool = False) -> _SnapshotLease:
        self._step(cleanup=cleanup)
        occupied = self._pool_check()
        _require(occupied < MAX_SNAPSHOT_FDS, "snapshot original descriptor capacity is exhausted")
        index = next(index for index, lease in enumerate(self._leases) if lease is None)
        lease = _SnapshotLease(self.cancellation, index)
        try:
            with self.cancellation.deferred(check_on_exit=False):
                self._accounting_pending = True
                self._leases[index] = lease  # Strong original custody BEFORE any open.
                self._reserved += 1
                self._peak = max(self._peak, occupied + 1)
                self._accounting_pending = False
        except BaseException as error:
            self._accounting_failed = True
            lease.failures.remember(error)
            raise
        return lease

    def _retire_lease(self, lease: _SnapshotLease) -> None:
        self._pool_check()
        slot = lease.slot
        _require(self._leases[lease.index] is lease and slot.pid == os.getpid()
                 and slot.thread is threading.current_thread() and lease.scope_returned
                 and not lease.scope_failed and lease.close.returned
                 and slot.number is None and slot.close_state == "CLOSED",
                 "snapshot original descriptor cleanup is unconfirmed")
        try:
            with self.cancellation.deferred(check_on_exit=False):
                self._accounting_pending = True
                self._leases[lease.index] = None  # Only a positively CLOSED original may leave.
                self._retired += 1
                self._accounting_pending = False
        except BaseException as error:
            self._accounting_failed = True
            lease.failures.remember(error)
            raise

    def _finish_lease(self, lease: _SnapshotLease, primary: BaseException | None = None) -> None:
        failures = lease.failures
        if primary is not None and failures.first is None:
            failures.first = primary
        try:
            try:
                error = failures.first
                lease.scope.__exit__(type(error) if error is not None else None, error,
                                     error.__traceback__ if error is not None else None)
                if self.pid == os.getpid():
                    lease.scope_returned = True
            except BaseException as error:
                lease.scope_failed = True
                failures.remember(error)
        finally:
            # If local callback dispatch failed before its close, a known
            # original still gets its sole _FD close. This cannot manufacture
            # the lost callback-return fact or retry an UNKNOWN numeric close.
            try:
                lease.slot.close()
            except BaseException as error:
                failures.remember(error)
        if self.pid == os.getpid():
            try:
                self._retire_lease(lease)
            except BaseException as error:
                failures.remember(error)
        else:
            failures.remember(ValidationError("inherited snapshot cannot retire parent originals"))
        failures.raise_first()

    @contextmanager
    def descriptor(self, path, flags, *, parent=None, cleanup: bool = False):
        lease = self._reserve_lease(cleanup=cleanup)
        try:
            try:
                lease.scope.__enter__()
                yield lease.slot.open(path, flags, dir_fd=parent)
            except BaseException as error:
                lease.failures.remember(error, abort=False)
        finally:
            self._finish_lease(lease)
        if not self.cancellation.depth:
            self.cancellation.check()

    def _node(self, parts: tuple[str, ...]) -> dict[str, Any]:
        return self.entries[parts] if parts else self.root_entry

    def _view(self, number: int, node: dict[str, Any], *, revision: bool) -> os.stat_result:
        observed = os.fstat(number)
        _require(node["state"] == "READY" and _directory(observed) == node["binding"],
                 "snapshot original directory binding changed")
        if revision:
            _require(_revision(observed) == node["revision"], "snapshot directory revision changed")
        return observed

    def _reserve_entry(self, parts: tuple[str, ...], kind: str,
                       parent: dict[str, Any]) -> dict[str, Any]:
        key = unicodedata.normalize("NFC", parts[-1]).casefold()
        _require(parts not in self.entries and key not in parent["children"]
                 and len(self.entries) < MAX_SNAPSHOT_ENTRIES,
                 "snapshot name is occupied, aliased or exceeds its bound")
        entry = self._entry(kind, parts)
        self.entries[parts] = entry
        parent["children"][key] = entry  # No rollback/adoption after an ambiguous effect.
        return entry

    @contextmanager
    def _walk(self, parts: tuple[str, ...], *, cleanup: bool = False,
              create_from: int | None = None):
        self._step(cleanup=cleanup)
        self._check()
        leases: list[_SnapshotLease] = []  # At most the fixed private path depth.
        failures = _SnapshotFailures(self.cancellation)
        try:
            number, node = self.slot.number, self.root_entry
            assert number is not None
            self._view(number, node, revision=not cleanup)
            for index, name in enumerate(parts, 1):
                self._step(cleanup=cleanup)
                # Existing components use direct original child records: no
                # repeated prefix tuple allocation/hash on every descent.
                key = unicodedata.normalize("NFC", name).casefold()
                entry = node["children"].get(key)
                creating = entry is None
                if creating:
                    _require(create_from is not None and index >= create_from,
                             "snapshot parent creation is unconfirmed")
                    entry = self._reserve_entry(parts[:index], "directory", node)
                else:
                    _require(entry["parts"][-1] == name and entry["kind"] == "directory" and entry["state"] == "READY"
                             and entry["binding"] is not None,
                             "snapshot parent creation is unconfirmed")
                lease = self._reserve_lease(cleanup=cleanup)
                leases.append(lease)  # Local close frame registered before mkdir/open.
                lease.scope.__enter__()
                parent = number
                if creating:
                    _mkdir_private(name, parent, self.cancellation, entry["creation"])
                number = lease.slot.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                         dir_fd=parent)
                observed = os.fstat(number)
                binding = _directory(observed)
                if creating:
                    _require(binding["uid"] == os.geteuid() and binding["mode"] == 0o700
                             and binding["device"] == self.identity["device"]
                             and _directory(os.stat(name, dir_fd=parent, follow_symlinks=False)) == binding,
                             "snapshot directory creation identity differs")
                    entry["binding"], entry["revision"], entry["state"] = binding, _revision(observed), "READY"
                    node["revision"] = _revision(self._view(parent, node, revision=False))
                else:
                    _require(binding == entry["binding"]
                             and _directory(os.stat(name, dir_fd=parent, follow_symlinks=False)) == binding,
                             "snapshot parent was replaced")
                    self._view(number, entry, revision=not cleanup)
                node = entry
            yield number
        except BaseException as error:
            failures.remember(error, abort=False)
        finally:
            for lease in reversed(leases):
                try:
                    self._finish_lease(lease, failures.first)
                except BaseException as error:
                    failures.remember(error)
            leases.clear()  # No healthy retired callback graph remains in a walk.
        failures.raise_first()
        if not self.cancellation.depth:
            self.cancellation.check()

    @contextmanager
    def directory(self, path: Path, *, cleanup: bool = False):
        with self._walk(self._parts(path), cleanup=cleanup) as number:
            yield number

    def mkdir(self, path: Path, *, parents: bool = False, exist_ok: bool = False) -> None:
        self._producer()
        parts = self._parts(path)
        _require(bool(parts), "snapshot root is already owned")
        if parts in self.entries:
            _require(exist_ok and self.entries[parts]["kind"] == "directory"
                     and self.entries[parts]["state"] == "READY",
                     "snapshot creation name is already reserved")
        with self._walk(parts, create_from=1 if parents else len(parts)):
            pass

    def protect_directory(self, path: Path) -> None:
        self._producer()
        parts = self._parts(path)
        with self.directory(path) as number:
            entry = self.entries[parts]
            entry["state"] = "MODE_ATTEMPTED"
            os.fchmod(number, 0o500)
            observed = os.fstat(number)
            changed = _directory(observed)
            _require(changed == {**entry["binding"], "mode": 0o500},
                     "snapshot directory mode transition differs")
            entry["binding"], entry["revision"], entry["state"] = changed, _revision(observed), "READY"

    def write_chunks(self, path: Path, blocks: Iterator[bytes], *, maximum: int,
                     executable: bool) -> _File:
        self._producer()
        parts = self._parts(path)
        _require(bool(parts), "snapshot root cannot be a file")
        count, digest, magic = 0, hashlib.sha256(), b""
        with self.directory(path.parent) as parent:
            parent_entry = self._node(parts[:-1])
            entry = self._reserve_entry(parts, "file", parent_entry)
            with self.descriptor(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 parent=parent) as number:
                created = _file(os.fstat(number))
                _require(created["uid"] == os.geteuid() and created["mode"] == 0o600
                         and created["links"] == 1 and created["device"] == self.identity["device"],
                         "snapshot output is not private and original")
                entry["created"] = created
                for block in blocks:
                    self._step()
                    _require(type(block) is bytes, "snapshot chunk is not immutable bytes")
                    count += len(block)
                    _require(count <= maximum <= MAX_FILE_BYTES, "snapshot output exceeds its bound")
                    if count == len(block):
                        magic = block[:4]
                    digest.update(block)
                    view = memoryview(block)
                    while view:
                        written = os.write(number, view)
                        _require(type(written) is int and 0 < written <= len(view),
                                 "snapshot output write made no progress")
                        view = view[written:]
                os.fchmod(number, 0o500 if executable else 0o400)
                os.fsync(number)
                binding = _file(os.fstat(number))
                _require(all(binding[key] == created[key] for key in ("device", "inode", "uid", "gid", "links"))
                         and binding["size"] == count and binding["mode"] == (0o500 if executable else 0o400)
                         and _file(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)) == binding,
                         "snapshot output changed during publication")
                entry["binding"] = binding
                parent_entry["revision"] = _revision(self._view(parent, parent_entry, revision=False))
            entry["state"] = "READY"
        return _File(count, digest.hexdigest(), magic)

    def copy_file(self, number: int, target: Path | None, budget: _Budget) -> _File:
        budget.tick()
        before = os.fstat(number)
        _require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE_BYTES,
                 "input must be a bounded regular file")
        count, digest, magic = 0, hashlib.sha256(), b""
        def chunks():
            nonlocal count, magic
            while data := os.read(number, CHUNK):
                budget.tick(len(data))
                count += len(data)
                _require(count <= before.st_size, "input grew during snapshotting")
                if count == len(data):
                    magic = data[:4]
                digest.update(data)
                yield data
        if target is None:
            for _ in chunks():
                pass
            result = _File(count, digest.hexdigest(), magic)
        else:
            result = self.write_chunks(target, chunks(), maximum=before.st_size,
                                       executable=bool(before.st_mode & 0o111))
        _require(count == before.st_size and _attributes(before) == _attributes(os.fstat(number)),
                 "input changed during snapshotting")
        budget.tick()
        return result

    def audit(self, *, cleanup: bool = False, failures: _SnapshotFailures | None = None) -> int:
        """Exact original inventory; timestamps alone never authorize a consumer.

        Cleanup records failed branches but may retire independently verified
        siblings. Its separate observed revision cannot repair producer state.
        """
        self._step(cleanup=cleanup)
        self._check()
        errors = failures if failures is not None else _SnapshotFailures(self.cancellation)
        self._audit_epoch += 1
        epoch, visited = self._audit_epoch, 0

        def check(number: int, node: dict[str, Any]) -> None:
            nonlocal visited
            self._step(cleanup=cleanup)
            before = self._view(number, node, revision=False)
            node["complete"], node["foreign"] = 0, False
            if _revision(before) != node["revision"]:
                errors.remember(ValidationError("iOS snapshot original directory revision changed"))
            count = 0
            try:
                with os.scandir(number) as iterator:
                    for observed in iterator:
                        self._step(cleanup=cleanup)
                        count += 1
                        visited += 1
                        _require(count <= MAX_FILES and visited <= MAX_SNAPSHOT_ENTRIES,
                                 "snapshot inventory exceeds its bound")
                        key = unicodedata.normalize("NFC", observed.name).casefold()
                        entry = node["children"].get(key)
                        if entry is None:
                            node["foreign"] = True
                            errors.remember(ValidationError("iOS snapshot contains a foreign entry"))
                            continue
                        parts = entry["parts"]
                        if observed.name != parts[-1] or entry["seen"] == epoch:
                            entry["conflict"] = epoch
                            node["foreign"] = True
                            errors.remember(ValidationError("iOS snapshot contains a foreign spelling/alias"))
                            continue
                        entry["seen"] = epoch
                        try:
                            details = observed.stat(follow_symlinks=False)
                            binding = _directory(details) if entry["kind"] == "directory" else _file(details)
                            _require(entry["state"] == "READY" and binding == entry["binding"],
                                     "snapshot entry changed or is unconfirmed")
                        except BaseException as error:
                            entry["conflict"] = epoch
                            errors.remember(error)
                after = self._view(number, node, revision=False)
                _require(_revision(after) == _revision(before), "snapshot changed during inventory")
                node["complete"], node["cleanup_revision"] = epoch, _revision(after)
            except BaseException as error:
                errors.remember(error)
            for entry in node["children"].values():
                parts = entry["parts"]
                if entry["seen"] != epoch:
                    entry["conflict"] = epoch
                    errors.remember(ValidationError("iOS snapshot original entry is missing"))
                if (node["complete"] != epoch or entry["kind"] != "directory"
                        or entry["conflict"] == epoch or self._walks_closed
                        or self._accounting_pending or self._accounting_failed):
                    continue
                try:
                    with self.descriptor(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                         parent=number, cleanup=cleanup) as child:
                        _require(_directory(os.fstat(child)) == entry["binding"]
                                 and _directory(os.stat(parts[-1], dir_fd=number,
                                                       follow_symlinks=False)) == entry["binding"],
                                 "snapshot directory was replaced during inventory")
                        check(child, entry)
                except BaseException as error:
                    entry["complete"] = 0
                    errors.remember(error)

        try:
            check(self.slot.number, self.root_entry)
        finally:
            check = None  # Break the finished recursive closure, not via GC.
        if failures is None:
            errors.raise_first()
        return epoch

    def admit(self, record, guard) -> None:
        self._producer()
        _require(guard is self.cancellation and self._lane_binding._record is record,
                 "snapshot admission has a different original owner")
        record._origin(guard)
        record._resource(self._lane_binding, self)
        self.audit()

    def _cleanup_view(self, number: int, node: dict[str, Any], epoch: int) -> None:
        observed = self._view(number, node, revision=False)
        _require(node["complete"] == epoch and _revision(observed) == node["cleanup_revision"],
                 "snapshot cleanup namespace changed after its complete inventory")

    def _make_writable(self, parts: tuple[str, ...], entry: dict[str, Any], epoch: int) -> None:
        _require(entry["seen"] == epoch and entry["conflict"] != epoch,
                 "snapshot directory is not independently checked")
        with self.directory(self._path.joinpath(*parts), cleanup=True) as number:
            self._cleanup_view(number, entry, epoch)
            if entry["binding"]["mode"] != 0o700:
                entry["state"] = "MODE_ATTEMPTED"
                os.fchmod(number, 0o700)
                observed = os.fstat(number)
                changed = _directory(observed)
                _require(changed == {**entry["binding"], "mode": 0o700},
                         "snapshot cleanup mode transition differs")
                entry["binding"], entry["state"] = changed, "READY"
                entry["cleanup_revision"] = _revision(observed)

    def _remove_entry(self, parts: tuple[str, ...], entry: dict[str, Any], epoch: int) -> None:
        _require(entry["state"] == "READY" and entry["binding"] is not None
                 and entry["seen"] == epoch and entry["conflict"] != epoch,
                 "snapshot entry creation, inventory or disposal is unconfirmed")
        parent_entry = self._node(parts[:-1])
        with self.directory(self._path.joinpath(*parts[:-1]), cleanup=True) as parent:
            self._cleanup_view(parent, parent_entry, epoch)
            observed = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            expected = _directory(observed) if entry["kind"] == "directory" else _file(observed)
            _require(expected == entry["binding"], "snapshot entry changed; preserve replacement")
            if entry["kind"] == "directory":
                _require(not entry["foreign"] and all(child["state"] == "REMOVED"
                         for child in entry["children"].values()), "snapshot has foreign or unsettled children")
                with self.directory(self._path.joinpath(*parts), cleanup=True) as number:
                    self._cleanup_view(number, entry, epoch)
                    with os.scandir(number) as iterator:
                        _require(next(iterator, None) is None, "snapshot contains an unknown survivor")
            entry["state"] = "REMOVE_ATTEMPTED"
            (os.rmdir if entry["kind"] == "directory" else os.unlink)(parts[-1], dir_fd=parent)
            try:
                os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                entry["state"] = "REMOVED"
            else:
                raise ValidationError("snapshot entry survived removal")
            parent_entry["cleanup_revision"] = _revision(self._view(parent, parent_entry, revision=False))

    def _dispose(self, *, recovery_idle: bool = False) -> None:
        self._owner(cleanup=True)
        _require(not recovery_idle and _consumer_idle(
            self.cancellation, lane_binding=self._lane_binding, owner=self),
            "original snapshot consumers are unconfirmed")
        _check_creation(self.creation, self.identity)
        if not self.created:
            return
        self._check()
        errors = self._cleanup_failures
        epoch = self.audit(cleanup=True, failures=errors)
        # Original ancestor reservations precede children. No sorted copy or
        # per-entry closure collection is needed in either disposal pass.
        for parts, entry in self.entries.items():
            if self._walks_closed or self._accounting_failed or self._accounting_pending:
                break
            if entry["kind"] == "directory":
                errors.attempt(self._make_writable, parts, entry, epoch)
        for parts in reversed(self.entries):
            if self._walks_closed or self._accounting_failed or self._accounting_pending:
                break
            errors.attempt(self._remove_entry, parts, self.entries[parts], epoch)
        if all(entry["state"] == "REMOVED" for entry in self.entries.values()):
            # The generic root disposer still requires original identity,
            # empty namespace, original settled consumers and root retirement.
            super()._dispose()
        else:
            errors.remember(ValidationError("iOS snapshot disposal is incomplete"))
        errors.raise_first()

    def _close_registry(self, errors: _SnapshotFailures, *, fork: bool = False) -> None:
        for index in range(MAX_SNAPSHOT_FDS - 1, -1, -1):
            lease = self._leases[index]
            if lease is None:
                continue
            if fork:
                errors.attempt(lease.slot.after_fork_child)
            else:
                errors.attempt(self._finish_lease, lease)

    def _close_parents(self, errors: _SnapshotFailures, *, fork: bool = False) -> None:
        for slot in reversed(self.parent.slots):
            errors.attempt(slot.after_fork_child if fork else slot.close)

    def cleanup(self) -> None:
        self._owner(cleanup=True)
        if self.claimed:
            return
        self.claimed, self.active = True, False
        errors = self._cleanup_failures
        try:
            try:
                self._dispose_callback()
            except BaseException as error:
                errors.remember(error)
        finally:
            try:
                self._registry_close_callback(errors)
            finally:
                try:
                    errors.attempt(self._root_close_callback)
                finally:
                    self._parents_close_callback(errors)
        errors.raise_first()
        _require(self._pool_check() == 0 and self._reserved == self._retired,
                 "snapshot original descriptor debt remains")
        self._cleanup_complete = True

    def _lane_closed_for(self, record, binding, guard) -> bool:
        self._owner(cleanup=True)
        if binding is not self._lane_binding or binding is None or guard is not self.cancellation:
            return False
        record._origin(guard)
        record._resource(binding, self)
        if not (self.claimed and not self.active and self._cleanup_complete and not self.created
                and self.creation["state"] in ("NEW", "NO_EFFECT", "RETIRED")
                and not self._accounting_pending and not self._accounting_failed
                and len(self._leases) == MAX_SNAPSHOT_FDS
                and self._cleanup_failures.first is None and not self._cleanup_failures.diagnostic_failed
                and self._reserved == self._retired and all(lease is None for lease in self._leases)):
            return False
        for slot in self.parent.slots:
            if not (slot.pid == self.pid and slot.thread is self.thread
                    and slot.number is None and slot.close_state == "CLOSED"):
                return False
        return (self.slot.pid == self.pid and self.slot.thread is self.thread
                and self.slot.number is None and self.slot.close_state == "CLOSED")

    def fork_close(self) -> None:
        self.active = False
        errors = self._fork_failures
        try:
            self._registry_close_callback(errors, fork=True)
        finally:
            try:
                errors.attempt(self.slot.after_fork_child)
            finally:
                self._parents_close_callback(errors, fork=True)
        errors.raise_first()


@contextmanager
def _source_descriptor(path, flags, *, parent=None, owner=None):
    if owner is None:
        number = os.open(path, flags, dir_fd=parent)
        try:
            yield number
        finally:
            os.close(number)
    else:
        with owner.descriptor(path, flags, parent=parent) as number:
            yield number


@contextmanager
def _source_file(path: Path, *, owner=None):
    if owner is None:
        with path.open("rb") as source:
            yield source
    else:
        with _source_descriptor(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, owner=owner) as number:
            # FileIO owns no numeric close. The prearmed original slot remains
            # the sole native FD owner even if a ZIP/file-object close fails.
            with io.FileIO(number, "rb", closefd=False) as source:
                yield source


def _copy_file(fd: int, target: Path | None, budget: _Budget, *, owner=None) -> _File:
    if owner is not None:
        return owner.copy_file(fd, target, budget)
    budget.tick()
    before = os.fstat(fd)
    _require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE_BYTES,
             "input must be a bounded regular file")
    digest, count, magic = hashlib.sha256(), 0, b""
    output = target.open("xb") if target is not None else None
    try:
        while data := os.read(fd, CHUNK):
            budget.tick(len(data))
            count += len(data)
            _require(count <= before.st_size, "input grew during snapshotting")
            if count == len(data):
                magic = data[:4]
            digest.update(data)
            if output is not None:
                output.write(data)
    finally:
        if output is not None:
            output.close()
    _require(count == before.st_size and _attributes(before) == _attributes(os.fstat(fd)),
             "input changed during snapshotting")
    if target is not None:
        target.chmod(0o555 if before.st_mode & 0o111 else 0o444)
    budget.tick()
    return _File(count, digest.hexdigest(), magic)


def _tree(path: Path, target: Path | None = None, *, deadline: InspectionDeadline, owner=None) -> Inventory:
    """Anchored descriptor traversal: never follow an input entry's symlink."""
    inventory: Inventory = {}
    paths, budget = _Paths(), _Budget(deadline)
    budget.tick()

    def walk(fd: int, relative: str, destination: Path | None) -> None:
        before = os.fstat(fd)
        _require(stat.S_ISDIR(before.st_mode), "tree input is not a directory")
        entries = []
        with os.scandir(fd) as iterator:
            for entry in iterator:
                budget.tick(entry=True)
                entries.append((entry.name, entry.stat(follow_symlinks=False)))
        for name, observed in sorted(entries):
            budget.tick()
            value = f"{relative}/{name}" if relative else name
            directory = stat.S_ISDIR(observed.st_mode)
            _require(directory or stat.S_ISREG(observed.st_mode), "symlink or special file in artifact tree")
            paths.add(value, directory)
            with _source_descriptor(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                                    (os.O_DIRECTORY if directory else 0), parent=fd, owner=owner) as child:
                _require(_attributes(observed) == _attributes(os.fstat(child)), "tree entry changed during snapshotting")
                output = destination / name if destination is not None else None
                if directory:
                    inventory[value] = None
                    if output is not None:
                        owner.mkdir(output) if owner is not None else output.mkdir(mode=0o700)
                    walk(child, value, output)
                    if output is not None:
                        owner.protect_directory(output) if owner is not None else output.chmod(0o500)
                else:
                    inventory[value] = _copy_file(child, output, budget, owner=owner)
        _require(_attributes(before) == _attributes(os.fstat(fd)), "tree layout changed during snapshotting")
        budget.tick()

    try:
        with _source_descriptor(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_DIRECTORY,
                                owner=owner) as fd:
            if target is not None:
                owner.mkdir(target) if owner is not None else target.mkdir(mode=0o700)
            walk(fd, "", target)
            if target is not None:
                owner.protect_directory(target) if owner is not None else target.chmod(0o500)
    except OSError as error:
        raise ValidationError("iOS artifact tree could not be read safely") from error
    return inventory


def _input(path: Path, target: Path | None = None, *, deadline: InspectionDeadline, owner=None) -> _File | Inventory:
    deadline.check()
    try:
        attributes = path.lstat()
        if stat.S_ISDIR(attributes.st_mode):
            return _tree(path, target, deadline=deadline, owner=owner)
        _require(stat.S_ISREG(attributes.st_mode), "input is not a regular file/directory")
        with _source_descriptor(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, owner=owner) as fd:
            _require(_attributes(attributes) == _attributes(os.fstat(fd)), "input path changed during snapshotting")
            return _copy_file(fd, target, _Budget(deadline), owner=owner)
    except OSError as error:
        raise ValidationError("iOS artifact input could not be read safely") from error


@dataclass
class IOSArtifactSnapshot:
    paths: dict[str, Path]
    originals: dict[str, Path]
    bindings: dict[str, _File | Inventory]
    temporary: Path
    deadline: InspectionDeadline
    unpacked: dict[str, Path] = field(default_factory=dict)
    cancellation: object | None = None
    _owner: _LaneSnapshotOwner | None = field(default=None, repr=False)

    def assert_unchanged(self) -> None:
        self.deadline.check()
        for name, original in self.originals.items():
            _require(_input(original, deadline=self.deadline, owner=self._owner) == self.bindings[name], "original artifact changed after snapshotting")
            _require(_input(self.paths[name], deadline=self.deadline, owner=self._owner) == self.bindings[name], "private snapshot changed during inspection")
        if self._owner is not None:
            self._owner.audit()
        self.deadline.check()

    def unpack(self, name: str) -> Path:
        self.deadline.check()
        if name in self.unpacked:
            if self._owner is not None:
                self._owner.audit()
            return self.unpacked[name]
        path = self.paths[name]
        if path.is_dir():
            if self._owner is not None:
                self._owner.audit()
            return path
        destination = self.temporary / (name + "-unpacked")
        safe_extract_zip(path, destination, deadline=self.deadline, _owner=self._owner)
        if name == "ios-ipa":
            self.unpacked[name] = destination
            if self._owner is not None:
                self._owner.audit()
            return destination
        root_name = "archive.xcarchive" if name == "ios-archive" else "dsyms"
        _require({item.name for item in destination.iterdir()} == {root_name} and
                 (destination / root_name).is_dir(), "packed archive/symbol root must be archive.xcarchive/ or dsyms/")
        self.unpacked[name] = destination / root_name
        if self._owner is not None:
            self._owner.audit()
        return self.unpacked[name]


@contextmanager
def snapshot_ios_artifacts(artifacts: Mapping[str, Path], *, cancellation=None,
                           lane_evidence=None) -> Iterator[IOSArtifactSnapshot]:
    """Only yielded private copies may be passed to native/content checks.

    A Store input binds its original finite owner before acquisition and never
    carries a delayed TemporaryDirectory finalizer. Standalone callers retain
    their existing scoped behavior.
    """
    deadline = InspectionDeadline()
    selected = {name: path for name, path in artifacts.items() if name in IOS_ARTIFACT_NAMES}
    owner = None
    if lane_evidence is not None:
        from ._store_lane_evidence import StoreLaneCallEvidence
        from .cancellation import DefaultCancellation

        _require(type(lane_evidence) is StoreLaneCallEvidence and type(cancellation) is DefaultCancellation,
                 "Store snapshot needs its original composite and cancellation owner")
        lane_evidence._origin(cancellation)
        owner = _LaneSnapshotOwner(cancellation, lane_evidence, deadline=deadline)
        context = _snapshot_scope(owner)
    else:
        context = first_primary_context(tempfile.TemporaryDirectory(prefix="mobile-release-ios-snapshot-"),
                                        cancellation=cancellation, expose_owner=True)
    with context as acquired:
        if owner is None:
            directory, cancellation = acquired
            temporary = Path(directory)
        else:
            _require(acquired is owner, "snapshot acquisition changed its original owner")
            temporary = owner._path
        copies, bindings = {}, {}
        for name, path in selected.items():
            _parts(path.name)
            parent = temporary / name
            owner.mkdir(parent) if owner is not None else parent.mkdir(mode=0o700)
            copies[name] = parent / path.name
            bindings[name] = _input(path, copies[name], deadline=deadline, owner=owner)
            if name == "ios-ipa":
                _require(isinstance(bindings[name], _File), "IPA must be a regular ZIP file")
        snapshot = IOSArtifactSnapshot(copies, selected, bindings, temporary, deadline,
                                       cancellation=cancellation, _owner=owner)
        if owner is not None:
            owner.audit()
        deadline.check()
        yield snapshot


def _zip_entry_offset(header: tuple[Any, ...], extra: bytes, *, deadline: InspectionDeadline) -> int:
    """Read only the ZIP64 fields needed to establish a single-disk offset."""
    offset, disk = header[16], header[13]
    if offset != 0xFFFFFFFF and disk != 0xFFFF:
        _require(disk == 0, "artifact ZIP must be single-disk")
        return offset
    position = 0
    zip64 = None
    while position < len(extra):
        deadline.check()
        _require(position + 4 <= len(extra), "artifact ZIP extra field is truncated")
        kind, length = struct.unpack_from("<HH", extra, position)
        position += 4
        _require(position + length <= len(extra), "artifact ZIP extra field exceeds its record")
        if kind == 1:
            _require(zip64 is None, "artifact ZIP has duplicate ZIP64 fields")
            zip64 = extra[position:position + length]
        position += length
    _require(zip64 is not None, "artifact ZIP is missing its ZIP64 offset")
    assert zip64 is not None
    position = 8 * ((header[9] == 0xFFFFFFFF) + (header[8] == 0xFFFFFFFF))
    if offset == 0xFFFFFFFF:
        _require(position + 8 <= len(zip64), "artifact ZIP64 offset is truncated")
        offset = struct.unpack_from("<Q", zip64, position)[0]
        position += 8
    if disk == 0xFFFF:
        _require(position + 4 <= len(zip64), "artifact ZIP64 disk is truncated")
        disk = struct.unpack_from("<I", zip64, position)[0]
    _require(disk == 0, "artifact ZIP must be single-disk")
    return offset


def _zip_directory_bound(archive: Path, *, deadline: InspectionDeadline, owner=None) -> int:
    """Bound the directory *before* stdlib's unbounded ZipInfo allocation.

    This is an allocation/layout gate, not a substitute for ZipFile's member
    validation, CRCs, complete inventory or authenticated evidence. The normalized iOS ZIP profile supports one disk, no prefix/trailer, and standard
    56-byte ZIP64 end records. Payload bytes are never read here.
    """
    deadline.check()
    with _source_file(archive, owner=owner) as source:
        size = os.fstat(source.fileno()).st_size
        _require(22 <= size <= MAX_FILE_BYTES, "artifact ZIP end record is missing")
        tail_size = min(size, 22 + 65535)
        source.seek(size - tail_size)
        tail = source.read(tail_size)
        # Match the exact EOCD selection used by ZipFile. A signature embedded
        # after the real EOCD must not let the two parsers disagree.
        # Match ZipFile's ordinary no-comment fast path. The offset/size fields
        # of a valid EOCD can themselves contain its signature byte sequence.
        end_index = (
            len(tail) - 22
            if len(tail) >= 22 and tail[-22:-18] == b"PK\x05\x06" and tail[-2:] == b"\0\0"
            else tail.rfind(b"PK\x05\x06")
        )
        _require(end_index >= 0 and end_index + 22 <= len(tail), "artifact ZIP end record is truncated")
        end = struct.unpack_from("<4s4H2IH", tail, end_index)
        _require(end_index + 22 + end[7] == len(tail), "artifact ZIP has trailing or ambiguous end data")
        end_offset = size - tail_size + end_index
        _require(end[1] == end[2] == 0 and end[3] == end[4], "artifact ZIP must be single-disk with consistent counts")
        count, directory_size, directory_offset = end[4:7]
        directory_end = end_offset
        source.seek(max(0, end_offset - 20))
        locator = source.read(20)
        if len(locator) == 20 and locator[:4] == b"PK\x06\x07":
            _, disk, zip64_offset, disks = struct.unpack("<4sIQI", locator)
            _require(disk == 0 and disks == 1 and zip64_offset + 56 == end_offset - 20, "artifact ZIP64 locator has an unsupported extent or disk")
            source.seek(zip64_offset)
            prefix = source.read(12)
            _require(len(prefix) == 12 and prefix[:4] == b"PK\x06\x06", "artifact ZIP64 end record is missing")
            # This bounded artifact profile deliberately excludes
            # extended records, even where ZipFile can support them. Never
            # allocate/read an extension from its untrusted 64-bit length.
            _require(struct.unpack_from("<Q", prefix, 4)[0] == 44, "artifact ZIP64 extended end records are unsupported")
            body = source.read(44)
            _require(len(body) == 44, "artifact ZIP64 end record is truncated")
            large = struct.unpack("<2H2I4Q", body)
            _require(large[2] == large[3] == 0 and large[4] == large[5], "artifact ZIP64 must be single-disk with consistent counts")
            for declared, actual, sentinel in zip((count, directory_size, directory_offset), large[5:8], (0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF)):
                _require(declared == sentinel or declared == actual, "artifact ZIP and ZIP64 directory records disagree")
            count, directory_size, directory_offset = large[5:8]
            directory_end = zip64_offset
        else:
            _require(count != 0xFFFF and directory_size != 0xFFFFFFFF and directory_offset != 0xFFFFFFFF, "artifact ZIP64 locator is missing")
        _require(0 < count <= MAX_FILES, "artifact ZIP member count is invalid")
        _require(46 * count <= directory_size <= MAX_ZIP_DIRECTORY, "artifact ZIP central directory exceeds its bounded size")
        _require(0 < directory_offset < directory_end and directory_offset + directory_size == directory_end, "artifact ZIP central directory extent is invalid")
        source.seek(0)
        _require(source.read(4) == b"PK\x03\x04", "artifact ZIP prefixes are unsupported")
        position, actual_count, first_local = directory_offset, 0, directory_offset
        while position < directory_end:
            deadline.check()
            _require(actual_count < MAX_FILES and position + 46 <= directory_end, "artifact ZIP central directory has excess or truncated entries")
            source.seek(position)
            fixed = source.read(46)
            _require(len(fixed) == 46 and fixed[:4] == b"PK\x01\x02", "artifact ZIP central directory record is invalid")
            header = struct.unpack("<4s6H3I5H2I", fixed)
            name_size, extra_size, comment_size = header[10:13]
            _require(0 < name_size <= 2048, "artifact ZIP filename exceeds its bounded size")
            following = position + 46 + name_size + extra_size + comment_size
            _require(following <= directory_end, "artifact ZIP central directory record exceeds its extent")
            source.seek(position + 46 + name_size)
            extra = source.read(extra_size)
            _require(len(extra) == extra_size, "artifact ZIP central directory extra field is truncated")
            local_offset = _zip_entry_offset(header, extra, deadline=deadline)
            _require(0 <= local_offset < directory_offset, "artifact ZIP local header offset is outside the payload")
            first_local = min(first_local, local_offset)
            actual_count += 1
            position = following
        _require(actual_count == count and first_local == 0, "artifact ZIP directory count or first header disagrees")
        deadline.check()
        return count


def safe_extract_zip(path: Path, destination: Path, *, deadline: InspectionDeadline | None = None,
                     _owner: _LaneSnapshotOwner | None = None) -> None:
    """Extract untrusted bytes into a new toolkit-owned directory, never app paths."""
    deadline = deadline if deadline is not None else InspectionDeadline()
    try:
        _zip_directory_bound(path, deadline=deadline, owner=_owner)
        with _source_file(path, owner=_owner) as original_source, zipfile.ZipFile(original_source) as archive:
            deadline.check()
            entries = archive.infolist()
            _require(0 < len(entries) <= MAX_FILES, "ZIP entry count exceeds its bound")
            paths, seen, total = _Paths(), set(), 0
            for entry in entries:
                deadline.check()
                directory = entry.is_dir()
                name = entry.filename[:-1] if directory else entry.filename
                _require(entry.orig_filename == entry.filename and name not in seen, "duplicate or NUL-containing ZIP entry")
                seen.add(name)
                paths.add(name, directory)
                mode = stat.S_IFMT(entry.external_attr >> 16)
                _require(mode in ({0, stat.S_IFDIR} if directory else {0, stat.S_IFREG}) and
                         not entry.flag_bits & 1 and entry.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED},
                         "ZIP contains links, special files, encryption or unsupported compression")
                total += entry.file_size
                _require(0 <= entry.file_size <= MAX_FILE_BYTES and total <= MAX_TOTAL_BYTES and
                         (not directory or entry.file_size == 0) and
                         entry.file_size <= max(1, entry.compress_size) * 1000,
                         "ZIP member expansion exceeds its bound")
            _owner.mkdir(destination) if _owner is not None else destination.mkdir(mode=0o700)
            budget = _Budget(deadline)
            for entry in entries:
                budget.tick(entry=True)
                target = destination.joinpath(*_parts(entry.filename.rstrip("/")))
                if entry.is_dir():
                    (_owner.mkdir(target, parents=True, exist_ok=True) if _owner is not None else
                     target.mkdir(parents=True, exist_ok=True, mode=0o700))
                    continue
                if _owner is not None:
                    _owner.mkdir(target.parent, parents=True, exist_ok=True)
                    size = 0
                    with archive.open(entry) as source:
                        def blocks():
                            nonlocal size
                            while data := source.read(CHUNK):
                                budget.tick(len(data))
                                size += len(data)
                                _require(size <= entry.file_size, "ZIP member exceeds its declared size")
                                yield data
                        _owner.write_chunks(target, blocks(), maximum=entry.file_size,
                                            executable=bool((entry.external_attr >> 16) & 0o111))
                    _require(size == entry.file_size, "ZIP member size differs from its declaration")
                    continue
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                size = 0
                with archive.open(entry) as source, target.open("xb") as output:
                    while data := source.read(CHUNK):
                        budget.tick(len(data))
                        size += len(data)
                        _require(size <= entry.file_size, "ZIP member exceeds its declared size")
                        output.write(data)
                _require(size == entry.file_size, "ZIP member size differs from its declaration")
                target.chmod(0o555 if (entry.external_attr >> 16) & 0o111 else 0o444)
            deadline.check()
    except (OSError, EOFError, ValueError, struct.error, zipfile.BadZipFile, NotImplementedError, zlib.error) as error:
        raise ValidationError("iOS artifact ZIP could not be extracted safely") from error


def typed_plist(path: Path, *, deadline: InspectionDeadline | None = None) -> Any:
    """Use the same complete bounded dictionary decoder as signed iOS policy."""
    deadline = deadline if deadline is not None else InspectionDeadline()
    deadline.check()
    try:
        _require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_PLIST_BYTES,
                 "Info.plist must be a bounded regular file")
        data = path.read_bytes()
        value = load_plist_dictionary(data, deadline=deadline)
        return typed_value(value, deadline=deadline)
    except OSError as error:
        raise ValidationError("iOS artifact Info.plist is malformed or exceeds its bounds") from error


@dataclass
class _Application:
    inventory: Inventory
    binaries: dict[str, tuple[MachOSlice, ...]]
    main: tuple[MachOSlice, ...]
    plists: dict[str, Any]


def _application(root: Path, expected_bundle_id: str, release: ReleaseVersion, *, deadline: InspectionDeadline) -> _Application:
    inventory = _tree(root, deadline=deadline)
    bundles = {""} | {name for name, value in inventory.items() if value is None and
                         PurePosixPath(name).suffix in {".app", ".appex", ".framework", ".xpc", ".bundle"}}
    plists, excluded, executables = {}, set(), {}
    for bundle in sorted(bundles):
        deadline.check()
        prefix = bundle + "/" if bundle else ""
        path = root / bundle
        info_name = prefix + "Info.plist"
        if info_name not in inventory and path.suffix == ".bundle":
            continue  # A plain resource directory is compared byte-for-byte.
        info = typed_plist(path / "Info.plist", deadline=deadline)
        plists[info_name] = info
        values = dict(info[1])
        executable = values.get("CFBundleExecutable")
        if path.suffix != ".bundle" or executable is not None:
            _require(executable is not None and executable[0] == "str" and len(_parts(executable[1])) == 1,
                     "bundle executable must be a safe basename")
            executables[bundle] = prefix + executable[1]
        identity = values.get("CFBundleIdentifier")
        _require(identity is not None and identity[0] == "str" and bool(identity[1]), "bundle lacks a string identity")
        for key in ("CFBundleVersion", "CFBundleShortVersionString"):
            _require(key not in values or values[key][0] == "str", "bundle version must be a string")
        if not bundle:
            _require(identity == ("str", expected_bundle_id), "primary Bundle ID differs from committed configuration")
        if not bundle or path.suffix in {".app", ".appex", ".xpc"}:
            _require(values.get("CFBundleVersion") == ("str", str(release.build)) and
                     values.get("CFBundleShortVersionString") == ("str", release.name),
                     "application/extension version differs from committed configuration")
        signature = prefix + "_CodeSignature"
        if signature in inventory:
            _require(inventory[signature] is None and
                     {name for name in inventory if name.startswith(signature + "/")} == {signature + "/CodeResources"} and
                     isinstance(inventory[signature + "/CodeResources"], _File), "signature directory contains unrecognized payload")
            excluded.update({signature, signature + "/CodeResources"})
        profile = prefix + "embedded.mobileprovision"
        if path.suffix in {".app", ".appex"} and profile in inventory:
            _require(isinstance(inventory[profile], _File), "embedded profile is not a regular file")
            excluded.add(profile)
    binaries = {}
    for name, value in inventory.items():
        deadline.check()
        if value is None:
            continue
        if value.magic in MACHO_MAGICS:
            _require(name not in excluded and "_CodeSignature" not in PurePosixPath(name).parts,
                     "native payload cannot hide in signature/profile exclusions")
            binaries[name] = inspect_macho(root / name, deadline=deadline)
        elif name.endswith(".dylib"):
            raise ValidationError("iOS artifact dylib is not a supported Mach-O image")
        if name.endswith("/Info.plist") or name == "Info.plist":
            plists[name] = typed_plist(root / name, deadline=deadline)
    _require(set(executables.values()) <= binaries.keys(), "declared bundle executable is not a supported Mach-O")
    return _Application({name: value for name, value in inventory.items() if name not in excluded},
                        binaries, binaries[executables[""]], plists)


def _identities(application: _Application, *, deadline: InspectionDeadline) -> dict[tuple[int, int, str], MachOSlice]:
    identities = {}
    for slices in application.binaries.values():
        deadline.check()
        for value in slices:
            _require(value.key not in identities or identities[value.key] == value,
                     "one UUID/architecture labels conflicting binary contents")
            identities[value.key] = value
    return identities


def _archive_application(archive: Path, expected_bundle_id: str, release: ReleaseVersion, *, deadline: InspectionDeadline) -> tuple[Path, _Application]:
    inventory = _tree(archive, deadline=deadline)
    _require({PurePosixPath(name).parts[0] for name in inventory} <= {"Info.plist", "Products", "dSYMs", "SwiftSupport"},
             "unsupported archive root (Watch/ODR/bitcode/recompiled or unknown ancillary content)")
    if "Info.plist" in inventory:
        typed_plist(archive / "Info.plist", deadline=deadline)
    apps = list((archive / "Products/Applications").iterdir())
    _require(len(apps) == 1 and apps[0].is_dir() and apps[0].suffix == ".app" and
             {item.name for item in (archive / "Products").iterdir()} == {"Applications"},
             "archive must contain exactly one Products/Applications app")
    return apps[0], _application(apps[0], expected_bundle_id, release, deadline=deadline)


def _require_symbols_policy(symbols_policy: str) -> None:
    _require(isinstance(symbols_policy, str) and symbols_policy in {"disabled", "retain", "required"},
             "unknown symbol policy")


def validate_present_symbols(archive: Path, application: _Application, *, symbols_policy: str,
                             deadline: InspectionDeadline) -> int:
    """Validate all present symbols and require every installed slice under retention."""
    _require_symbols_policy(symbols_policy)
    deadline.check()
    identities, symbols = _identities(application, deadline=deadline), set()
    directory = archive / "dSYMs"
    inventory = _tree(directory, deadline=deadline) if directory.is_dir() else {}
    owners = {PurePosixPath(name).parts[0] for name in inventory}
    _require(all(name.endswith(".dSYM") and inventory.get(name) is None for name in owners),
             "dSYMs must contain only regular dSYM bundles")
    validated_dwarf = set()
    for owner in sorted(owners):
        deadline.check()
        typed_plist(directory / owner / "Contents/Info.plist", deadline=deadline)
        prefix = owner + "/Contents/Resources/DWARF/"
        dwarf = [name for name, value in inventory.items() if name.startswith(prefix) and isinstance(value, _File)]
        _require(bool(dwarf), "retained dSYM lacks a DWARF object")
        for name in dwarf:
            _require("/" not in name[len(prefix):], "DWARF objects must be direct regular children")
            for value in inspect_macho(directory / name, dsym=True, deadline=deadline):
                _require(value.key in identities and value.key not in symbols,
                         "retained dSYM is unknown, substituted or duplicated")
                symbols.add(value.key)
            validated_dwarf.add(name)
    for name, value in inventory.items():
        deadline.check()
        if isinstance(value, _File) and value.magic in MACHO_MAGICS:
            _require(name in validated_dwarf, "native object outside retained DWARF inventory")
    if symbols_policy in {"retain", "required"}:
        _require(identities.keys() == symbols, "retained symbols are missing for installed native slices")
    deadline.check()
    return len(symbols)


def inspect_archive_symbols(archive: Path, *, expected_bundle_id: str, release: ReleaseVersion,
                            symbols_policy: str, deadline: InspectionDeadline | None = None) -> int:
    deadline = deadline if deadline is not None else InspectionDeadline()
    deadline.check()
    _require_symbols_policy(symbols_policy)
    _path, application = _archive_application(archive, expected_bundle_id, release, deadline=deadline)
    return validate_present_symbols(archive, application, symbols_policy=symbols_policy, deadline=deadline)


def _support(root: Path, application: _Application, *, deadline: InspectionDeadline) -> dict[str, tuple[MachOSlice, ...]]:
    deadline.check()
    if not root.exists():
        return {}
    inventory = _tree(root, deadline=deadline)
    _require(inventory.get("iphoneos", False) is None and all(name == "iphoneos" or
             (len(PurePosixPath(name).parts) == 2 and name.startswith("iphoneos/") and
              name.endswith(".dylib") and isinstance(value, _File)) for name, value in inventory.items()),
             "SwiftSupport must contain only iphoneos dylibs")
    result = {}
    for name, value in inventory.items():
        deadline.check()
        if value is None:
            continue
        support = inspect_macho(root / name, deadline=deadline)
        shipped = [slices for path, slices in application.binaries.items() if PurePosixPath(path).name == PurePosixPath(name).name]
        _require(bool(shipped), "SwiftSupport library has no shipped counterpart")
        for slices in shipped:
            _require(set(slices) <= set(support), "shipped runtime slices differ from SwiftSupport")
        result[name] = support
    _require(bool(result), "SwiftSupport must not be an empty ancillary root")
    return result


def inspect_ios_artifact_set(snapshot: IOSArtifactSnapshot, *, expected_bundle_id: str,
                             release: ReleaseVersion, symbols_policy: str) -> dict[str, int]:
    """Inspect the complete pair before any new intent/Store preparation."""
    deadline = snapshot.deadline
    deadline.check()
    _require_symbols_policy(symbols_policy)
    _require({"ios-ipa", "ios-archive"} <= snapshot.paths.keys(), "signed IPA validation requires its retained xcarchive")
    try:
        archive = snapshot.unpack("ios-archive")
        ipa = snapshot.unpack("ios-ipa")
        app_path, original = _archive_application(archive, expected_bundle_id, release, deadline=deadline)
        _require({item.name for item in ipa.iterdir()} <= {"Payload", "SwiftSupport"},
                 "unsupported IPA root (Watch/ODR/bitcode/recompiled or unknown ancillary content)")
        apps = list((ipa / "Payload").iterdir())
        _require(len(apps) == 1 and apps[0].name == app_path.name and apps[0].is_dir(),
                 "IPA and archive primary application paths differ")
        exported = _application(apps[0], expected_bundle_id, release, deadline=deadline)
        _require(original.inventory.keys() == exported.inventory.keys(), "IPA/archive file or nested bundle inventory differs")
        _require(original.binaries == exported.binaries, "IPA/archive Mach-O identity/content differs (recompiled, stripped, thinned or substituted)")
        _require(original.plists == exported.plists, "IPA/archive typed Info.plist contents differ")
        for name, value in original.inventory.items():
            deadline.check()
            if name not in original.binaries and name not in original.plists:
                _require(value == exported.inventory[name], "IPA/archive non-signature resources differ")
        symbols = validate_present_symbols(archive, original, symbols_policy=symbols_policy, deadline=deadline)
        if "ios-dsyms" in snapshot.paths:
            detached = snapshot.unpack("ios-dsyms")
            _require((archive / "dSYMs").is_dir() and _tree(detached, deadline=deadline) == _tree(archive / "dSYMs", deadline=deadline),
                     "detached dSYMs differ from the retained archive")
        _require(_support(archive / "SwiftSupport", original, deadline=deadline) == _support(ipa / "SwiftSupport", exported, deadline=deadline),
                 "IPA/archive SwiftSupport inventories or contents differ")
        snapshot.assert_unchanged()
        return {"nativePaths": len(original.binaries), "nativeIdentities": len(_identities(original, deadline=deadline)),
                "presentSymbolSlices": symbols}
    except OSError as error:
        raise ValidationError("iOS artifact pair has a missing or unreadable required path") from error
