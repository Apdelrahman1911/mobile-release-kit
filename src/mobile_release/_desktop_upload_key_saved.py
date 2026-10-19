"""Finite read-only saved-config originals of the SAME generation helper.

No draft/path/hash by itself is authority. Native supplies a retained returned
saved-input lane; this helper still opens and rechecks the exact registered
root and the sole fixed config before private GO and both fixed commands.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat

from . import _desktop_upload_key_protocol as wire
from .build_inputs import _Directory, _FD, _cleanup_failure
from .cancellation import DefaultCancellation
from .config import MAX_CONFIG_BYTES, parse_config_text
from .metadata import check_metadata_text


def _directory(value):
    wire.require(stat.S_ISDIR(value.st_mode))
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def bind_saved_bytes(raw, expected: wire.SavedProject) -> None:
    """Pure comparison over the held file's bounded bytes, not a read grant."""
    wire.require(type(expected) is wire.SavedProject and type(raw) in (bytes, bytearray, memoryview)
                 and len(raw) == expected.config_bytes and len(raw) <= MAX_CONFIG_BYTES
                 and hashlib.sha256(raw).hexdigest() == expected.config_sha256)
    text = bytes(raw).decode("utf-8")
    wire.require(not any(code == "metadata.secret-pattern"
                         for code, _ in check_metadata_text("saved-upload-key", text).issues))
    data = parse_config_text(text)
    canonical = json.dumps(data, sort_keys=True, ensure_ascii=False,
                           separators=(",", ":"), allow_nan=False).encode("utf-8")
    wire.require(hashlib.sha256(canonical).hexdigest() == expected.draft_sha256
                 and data["android"].get("enabled") is True)
    app = data["android"]["applicationId"].encode("ascii")
    identity = hashlib.sha256(b"dev.mobile-release-kit.desktop/credential-app-identity/v1\0"
                              + b"\x01" + len(app).to_bytes(4, "big") + app).hexdigest()
    wire.require(identity == expected.app_identity_sha256)


class UploadKeySaved:
    def __init__(self, expected: wire.SavedProject, guard: DefaultCancellation) -> None:
        wire.require(type(expected) is wire.SavedProject and type(guard) is DefaultCancellation)
        self.expected, self.guard = expected, guard
        self.root = _Directory(expected.root, guard)
        self.release, self.file = _FD(guard), _FD(guard)
        self.release_identity = self.file_identity = None
        self.raw = bytearray(MAX_CONFIG_BYTES)  # Retained before first file read.
        self.length = 0
        self.admitted = self.closed = self.unknown = False

    def acquire(self) -> None:
        wire.require(not self.admitted and not self.closed)
        self.guard.check()
        self.root.acquire()
        wire.require(_directory(os.fstat(self.root.fd)) == self.expected.root_identity)
        release = self.release.open("release", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=self.root.fd)
        self.release_identity = _directory(os.fstat(release))
        number = self.file.open("mobile-release.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                               dir_fd=release)
        value = os.fstat(number)
        wire.require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1
                     and 0 < value.st_size <= MAX_CONFIG_BYTES)
        self.file_identity = wire.identity(value)
        self._read()
        bind_saved_bytes(memoryview(self.raw)[:self.length], self.expected)
        self.admitted = True

    def _names(self) -> None:
        self.guard.check()
        self.root.check()
        wire.require(_directory(os.fstat(self.root.fd)) == self.expected.root_identity
                     and self.release.number is not None and self.file.number is not None
                     and self.release.close_state == self.file.close_state == "NOT_ATTEMPTED"
                     and _directory(os.fstat(self.release.number)) == self.release_identity
                     and _directory(os.stat("release", dir_fd=self.root.fd, follow_symlinks=False)) == self.release_identity
                     and wire.identity(os.fstat(self.file.number)) == self.file_identity
                     and wire.identity(os.stat("mobile-release.json", dir_fd=self.release.number,
                                               follow_symlinks=False)) == self.file_identity)

    def _read(self) -> None:
        self._names()
        size = self.file_identity[6]
        wire.require(size == self.expected.config_bytes)
        os.lseek(self.file.number, 0, os.SEEK_SET)
        self.length = 0
        while self.length < size:
            self.guard.check()
            count = os.readv(self.file.number, [memoryview(self.raw)[self.length:size]])
            wire.require(type(count) is int and 0 < count <= size - self.length)
            self.length += count
        wire.require(os.read(self.file.number, 1) == b"")
        self._names()
        wire.require(hashlib.sha256(memoryview(self.raw)[:self.length]).hexdigest() == self.expected.config_sha256)

    def check(self) -> None:
        wire.require(self.admitted and not self.closed and not self.unknown)
        self._read()  # SAME held original, never a replacement path parse.

    def close(self) -> None:
        if self.closed:
            return
        first = None
        for close in (self.file.close, self.release.close, self.root.close):
            try:
                close()
            except BaseException as error:
                self.unknown = True
                _cleanup_failure(self.guard, error)
                if first is None:
                    first = error
        self.closed = (not self.unknown and self.file.close_state == self.release.close_state == "CLOSED"
                       and all(slot.close_state == "CLOSED" for slot in self.root.slots))
        if not self.closed:
            self.unknown = True
            if first is None:
                first = wire.ProtocolError("The saved upload-key input did not settle")
                _cleanup_failure(self.guard, first)
        if first is not None:
            raise first

    def clear(self) -> None:
        wire.require(self.closed and not self.unknown)
        self.raw[:] = b"\0" * len(self.raw)
        self.length = 0
