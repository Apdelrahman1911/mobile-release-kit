"""One original receive-pack body, retained by the existing helper/view owners.

This facet never opens/adopts/closes/unlinks a descriptor. Its two actual leases
must come from the fixed helper's SAME Acquisition and the admitted private view;
the native entry/lease-kind hooks remain a separate, unavailable dependency.
Byte seal and send completion are not durable ACK, permission or native finality.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

from . import _native_process as native
from . import git_push_wire as wire


NAME = "request-body"
SEND_CHUNK = 64 * 1024
IO_CALLS = 24_000  # Includes known short returns; never an unbounded retry loop.
WORKING_RESERVE = 16 * 1024 * 1024  # Separate original Push charge, not Fetch spare or an RSS claim.
_KEY = object()


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_uid, info.st_gid, info.st_nlink)


def _identity(value):
    return (type(value) is tuple and len(value) == 9
            and all(type(part) is int and part >= 0 for part in value))


class _BodyIO:
    """Borrowed original leases; one fixed buffer, count-only native returns.

    In particular, Acquisition._Call must not retain every bytes object read
    from the pack. libc reads/writes return counts against this SAME buffer.
    Their actual records and this buffer still require the original census.
    """
    def __init__(self, acquisition, parent, file, path, parent_stamp, file_stamp, current, *, _key):
        wire._need(_key is _KEY and type(acquisition) is native.Acquisition
                   and type(parent) is native.FDLease and type(file) is native.FDLease
                   and parent is not file and parent._owner is file._owner is acquisition
                   and parent._kind == "git_push_directory" and file._kind == "git_push_body"
                   and parent._access == os.O_RDONLY and file._access == os.O_RDWR
                   and type(path) is type(Path()) and path.is_absolute()
                   and len(os.fsencode(path)) <= 4096 and callable(current)
                   and _identity(parent_stamp) and _identity(file_stamp))
        self.acquisition, self.parent, self.file, self.path = acquisition, parent, file, path
        self.parent_stamp, self.original, self.current = parent_stamp, file_stamp, current
        self.runtime = acquisition._runtime()
        self.calls = 0
        self.failed = False
        c = self.runtime.abi.c
        self.buffer = (c.c_ubyte * SEND_CHUNK)()
        for name in ("read", "write"):
            wire._need("git_push_body_" + name not in self.runtime.functions)
            function = self.runtime.library[name]
            function.argtypes = [c.c_int, c.c_void_p, c.c_size_t]
            function.restype = c.c_ssize_t
            self.runtime.functions["git_push_body_" + name] = function
        wire._need(stat.S_ISDIR(parent_stamp[2]) and stat.S_IMODE(parent_stamp[2]) == 0o700
                   and parent_stamp[6] == os.getuid()
                   and stat.S_ISREG(file_stamp[2]) and stat.S_IMODE(file_stamp[2]) == 0o600
                   and file_stamp[3] == 0 and file_stamp[6] == os.getuid() and file_stamp[8] == 1)
        self.check(file_stamp)

    def __repr__(self):
        return "<original private Push body IO>"

    def _call(self, name, function, *args, mutating=True):
        wire._need(not self.failed and self.calls < IO_CALLS, "response-limit")
        self.calls += 1
        try:
            self.acquisition._check()
            self.current()
            value = self.acquisition._invoke(name, function, *args, roots=(self, self.file, self.parent),
                                             mutating=mutating)
            self.current()
            return value
        except BaseException:
            self.failed = True
            raise

    def check(self, expected=None):
        """Full forward-edge rematch; content transitions are checked by seal."""
        file_fd, parent_fd = self.file.fileno(), self.parent.fileno()
        actual_parent = _stamp(self._call("git_push_parent_stat", os.fstat, parent_fd, mutating=False))
        path_parent = _stamp(self._call("git_push_parent_path", self.path.lstat, mutating=False))
        actual = _stamp(self._call("git_push_body_stat", os.fstat, file_fd, mutating=False))
        # os.stat kwargs cannot be forwarded through Acquisition._invoke.
        # The fixed bound method has no caller-selected name or symlink mode.
        def entry():
            return os.stat(NAME, dir_fd=parent_fd, follow_symlinks=False)
        named = _stamp(self._call("git_push_body_entry", entry, mutating=False))
        wire._need(actual_parent == path_parent == self.parent_stamp and named == actual)
        wire._need(actual[:3] == self.original[:3] and actual[6:] == self.original[6:]
                   and (expected is None or actual == expected))
        self.current()
        return actual

    def write(self, data):
        wire._need(type(data) is bytes and 0 < len(data) <= wire.READ_CHUNK)
        self.buffer[:len(data)] = data
        count = self._call("git_push_body_write", self.runtime.call, "git_push_body_write",
                           self.file.fileno(), self.buffer, len(data))
        wire._need(type(count) is int and 0 < count <= len(data))
        return count

    def read(self, maximum):
        wire._need(type(maximum) is int and 0 < maximum <= SEND_CHUNK)
        count = self._call("git_push_body_read", self.runtime.call, "git_push_body_read",
                           self.file.fileno(), self.buffer, maximum, mutating=False)
        wire._need(type(count) is int and 0 <= count <= maximum)
        return bytes(self.buffer[:count])

    def rewind(self):
        value = self._call("git_push_body_rewind", os.lseek, self.file.fileno(), 0, os.SEEK_SET)
        wire._need(type(value) is int and value == 0)

    def sync(self):
        wire._need(self._call("git_push_body_sync", os.fsync, self.file.fileno()) is None)


class _PushBody:
    """One fixed body slot, published on the actual helper before any write.

    The entry creates its original leases before constructing this facet and
    retains them through ordinary-IO close and returned-frame/C/A/W joins.
    There is intentionally no public issuer or open-by-path fallback here.
    """
    def __init__(self, io: _BodyIO, selected: wire.Selection, offered: wire.Advertisement):
        wire._need(type(io) is _BodyIO and type(selected) is wire.Selection)
        wire._original(offered, selected)
        self.io, self.selected, self.offered = io, selected, offered
        self.request = self.stream = self.digest = self.sealed_stamp = None
        self.phase = "empty"
        self.entered = self.failed = False
        self.written = self.sent = 0

    def __repr__(self):
        return "<original private receive-pack body>"

    def _enter(self, phase):
        wire._need(not self.entered and not self.failed and not self.io.failed and self.phase == phase)
        self.entered = True

    def _write(self, raw):
        for start in range(0, len(raw), wire.READ_CHUNK):
            block = raw[start:start + wire.READ_CHUNK]
            offset = 0
            while offset < len(block):
                self.io.current()
                count = self.io.write(block[offset:])
                wire._need(type(count) is int and 0 < count <= len(block) - offset)
                self.written += count
                offset += count  # Only a genuinely returned short write.
                self.io.current()

    def begin(self, request: wire.Command):
        self._enter("empty")
        self.phase = "collecting"  # Before the first original callback/effect.
        try:
            wire._need(type(request) is wire.Command
                       and wire.command(request.raw, self.selected, self.offered) == request)
            self.request = request
            self.stream = wire.PackStream(request, self.selected, self.offered)
            self.io.check(self.io.original)
            self._write(request.raw)
        except BaseException:
            self.failed = True
            raise
        finally:
            self.entered = False

    def append(self, block: bytes):
        self._enter("collecting")
        try:
            self.stream.feed(block)  # Includes aggregate cap before any write.
            self._write(block)
        except BaseException:
            self.failed = True
            raise
        finally:
            self.entered = False

    def seal(self) -> wire.BodyDigest:
        self._enter("collecting")
        self.phase = "sealing"
        try:
            digest = self.stream.finish()
            wire._need(digest.body_bytes == self.written)
            self.io.sync()
            original = self.io.check()
            wire._need(original[3] == digest.body_bytes)
            self.io.rewind()
            actual, count = hashlib.sha256(), 0
            while True:
                block = self.io.read(min(SEND_CHUNK, digest.body_bytes + 1 - count))
                if not block:
                    break
                count += len(block)
                wire._need(count <= digest.body_bytes, "response-limit")
                actual.update(block)
            wire._need(count == digest.body_bytes and actual.hexdigest() == digest.body_sha256)
            self.io.check(original)
            self.io.current()
            self.digest, self.sealed_stamp = digest, original
            self.phase = "sealed"
            return digest
        except BaseException:
            self.failed = True
            raise
        finally:
            self.entered = False

    def claim_send(self, request: wire.Command):
        self._enter("sealed")
        self.phase = "send-claimed"
        try:
            # Equal serialized fields do not substitute a different original
            # helper round. This is a body-use claim, NEVER the journal ACK.
            wire._need(request is self.request and self.digest is not None)
            self.io.check(self.sealed_stamp)
            self.io.current()
        except BaseException:
            self.failed = True
            raise
        finally:
            self.entered = False

    def send(self, write, before_write):
        """Only called inside the SAME fixed HTTP connection's try/finally."""
        self._enter("send-claimed")
        self.phase = "sending"
        try:
            wire._need(callable(write) and callable(before_write))
            self.io.check(self.sealed_stamp)
            self.io.rewind()
            digest = hashlib.sha256()
            while self.sent < self.digest.body_bytes:
                self.io.current()
                block = self.io.read(min(SEND_CHUNK, self.digest.body_bytes - self.sent))
                wire._need(bool(block) and len(block) <= self.digest.body_bytes - self.sent)
                before_write()
                wire._need(write(block) is None)  # Never replay a partial/raised send.
                self.sent += len(block)
                digest.update(block)
                self.io.current()
            wire._need(self.io.read(1) == b"" and digest.hexdigest() == self.digest.body_sha256)
            self.io.check(self.sealed_stamp)
            self.io.current()
            self.phase = "sent"
        except BaseException:
            self.failed = True
            raise
        finally:
            self.entered = False
