"""One original mutable JKS inode; not adoption of keytool-created output.

The app creates and holds a valid empty JKS before the fixed keytool call.
Only that exact inode may change. Foreign entries, replaced names and unknown
producers are preserved. No recursive deletion, automatic finalizer or retry.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from . import _desktop_upload_key_jks as jks
from . import _desktop_upload_key_protocol as wire
from ._tool_acquisition_files import _Scan
from .build_inputs import (_Directory, _FD, _cleanup_failure, _consumer_idle, _directory,
                           _file, _mkdir_private)
from .cancellation import DefaultCancellation


class UploadKeyScratch:
    def __init__(self, parent: Path, operation_id: str, guard: DefaultCancellation) -> None:
        wire.require(type(guard) is DefaultCancellation)
        wire._id(operation_id)
        self.guard = guard
        self.name = ".mrk-upload-key-" + operation_id
        self.parent = _Directory(parent, guard, system_root_aliases=True)
        self.path = parent / self.name
        self.creation = {"state": "NEW"}
        self.directory, self.file = _FD(guard), _FD(guard)
        self.directory_identity = self.file_identity = None
        self.remove_file_claimed = self.remove_directory_claimed = False
        self.file_removed = self.directory_removed = False
        self.unknown = self.closed = False
        self.scan = None
        self.raw = bytearray(wire.JKS_LIMIT)  # Retained BEFORE any private read/acquisition.
        self.length = 0

    def acquire(self) -> None:
        self.guard.check()
        wire.require(self.creation["state"] == "NEW" and not self.closed)
        self.parent.acquire()
        self.path = self.parent.path / self.name
        _mkdir_private(self.name, self.parent.fd, self.guard, self.creation)
        number = self.directory.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                     dir_fd=self.parent.fd)
        observed = os.fstat(number)
        wire.require(stat.S_IMODE(observed.st_mode) == 0o700 and observed.st_uid == os.geteuid()
                     and observed.st_gid == os.getegid())
        self.directory_identity = _directory(observed)
        self.check()
        self.guard.check()

    def _names(self) -> set[str]:
        wire.require(self.directory.number is not None and
                     (self.scan is None or self.scan.state == "CLOSED"))
        self.scan = _Scan(self.guard)  # Same reviewed original iterator owner.
        names = set()
        try:
            self.scan.open(self.directory.number)
            for entry in self.scan.original:
                wire.require(len(names) < 2)
                names.add(entry.name)
        finally:
            try:
                self.scan.close()
            except BaseException as error:
                self.unknown = True
                _cleanup_failure(self.guard, error)
                raise
        return names

    def check(self) -> None:
        wire.require(not self.closed and not self.unknown and self.creation["state"] == "CREATED"
                     and self.directory_identity is not None and self.directory.number is not None)
        self.parent.check()
        wire.require(_directory(os.fstat(self.directory.number)) == self.directory_identity
                     and _directory(os.stat(self.name, dir_fd=self.parent.fd, follow_symlinks=False))
                     == self.directory_identity)
        names = self._names()
        wire.require(names == (set() if self.file_identity is None else {"upload.jks"}))
        if self.file_identity is not None:
            wire.require(self.file.number is not None)
            opened = os.fstat(self.file.number)
            named = os.stat("upload.jks", dir_fd=self.directory.number, follow_symlinks=False)
            wire.require(self._stable(opened) == self.file_identity == self._stable(named)
                         and 0 <= opened.st_size <= wire.JKS_LIMIT and _file(opened) == _file(named))

    @staticmethod
    def _stable(value):
        wire.require(stat.S_ISREG(value.st_mode))
        return (value.st_dev, value.st_ino, value.st_uid, value.st_gid,
                stat.S_IMODE(value.st_mode), value.st_nlink)

    def initialize(self, password) -> None:
        self.guard.check()
        self.check()
        wire.require(self.file_identity is None and self.file.open_state == "NEW")
        number = self.file.open("upload.jks", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                0o600, dir_fd=self.directory.number)
        observed = os.fstat(number)
        self.file_identity = self._stable(observed)  # Original creator/FD, not later path adoption.
        wire.require(observed.st_uid == os.geteuid() and observed.st_gid == os.getegid()
                     and stat.S_IMODE(observed.st_mode) == 0o600 and observed.st_nlink == 1
                     and observed.st_size == 0)
        original = jks.empty_jks(password)
        try:
            view = memoryview(original)
            while view:
                self.guard.check()
                count = os.write(number, view)
                wire.require(type(count) is int and 0 < count <= len(view))
                view = view[count:]
            os.fsync(number)
        finally:
            original[:] = b"\0" * len(original)
        self.check()
        self.read_original()
        jks.check_empty(memoryview(self.raw)[:self.length], password)
        self.clear_result()

    def read_original(self) -> None:
        self.guard.check()
        self.check()
        wire.require(self.file.number is not None)
        before = _file(os.fstat(self.file.number))
        wire.require(0 < before["size"] <= wire.JKS_LIMIT)
        os.lseek(self.file.number, 0, os.SEEK_SET)
        self.length = 0
        while self.length < before["size"]:
            self.guard.check()
            count = os.readv(self.file.number, [memoryview(self.raw)[self.length:before["size"]]])
            wire.require(type(count) is int and 0 < count <= before["size"] - self.length)
            self.length += count
        wire.require(os.read(self.file.number, 1) == b"" and _file(os.fstat(self.file.number)) == before)
        self.check()

    def clear_result(self) -> None:
        self.raw[:] = b"\0" * len(self.raw)
        self.length = 0

    def cleanup(self) -> None:
        if self.closed:
            return
        first = None
        try:
            wire.require(not self.unknown and self.creation["state"] not in ("ATTEMPTED", "UNKNOWN"))
            if self.creation["state"] == "CREATED":
                # Only original C/A/W ledger/no-producer facts allow namespace
                # cleanup. A terminal header/export/fingerprint never does.
                wire.require(_consumer_idle(self.guard))
                self.check()
                if self.file_identity is not None:
                    wire.require(not self.remove_file_claimed)
                    self.remove_file_claimed = True
                    os.unlink("upload.jks", dir_fd=self.directory.number)
                    self.file_removed = True
                wire.require(self._names() == set() and not self.remove_directory_claimed)
                self.parent.check()
                wire.require(_directory(os.stat(self.name, dir_fd=self.parent.fd, follow_symlinks=False))
                             == self.directory_identity)
                self.remove_directory_claimed = True
                os.rmdir(self.name, dir_fd=self.parent.fd)
                self.directory_removed = True
        except BaseException as error:
            first, self.unknown = error, True
            _cleanup_failure(self.guard, error)
        # Even if namespace cleanup refuses, attempt each independent original
        # descriptor close ONCE. Keep this book/partial on any unknown outcome.
        for close in (self.file.close, self.directory.close, self.parent.close):
            try:
                close()
            except BaseException as error:
                self.unknown = True
                _cleanup_failure(self.guard, error)
                if first is None:
                    first = error
        self.closed = (not self.unknown and self.file.close_state == self.directory.close_state == "CLOSED"
                       and all(slot.close_state == "CLOSED" for slot in self.parent.slots)
                       and (self.scan is None or self.scan.state == "CLOSED"))
        if not self.closed and first is None:
            self.unknown = True
            first = wire.ProtocolError("The original upload-key scratch did not settle")
            _cleanup_failure(self.guard, first)
        if first is not None:
            raise first
