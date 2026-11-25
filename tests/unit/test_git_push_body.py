"""Same production body/Acquisition with finite fake syscall returns only.

No real FD, syscall, helper, network, journal ACK or native admission is made.
The fake table supplies exact original return cuts, not a native close proof.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import Path
import stat
import threading
import types
import unittest
from unittest.mock import patch

from mobile_release import _native_process as native
from mobile_release import git_push_body as body
from mobile_release import git_push_wire as wire
from test_git_push_wire import SELECTED, command, offered, pack


class _Returns:
    def __init__(self, test):
        self.path = Path("/fixed-original-view")
        self.parent = (1, 2, stat.S_IFDIR | 0o700, 80, 100, 100, 501, 20, 2)
        self.original = (1, 3, stat.S_IFREG | 0o600, 0, 100, 100, 501, 20, 1)
        self.file_stamp = self.original
        self.content, self.offset, self.tick = bytearray(), 0, 100
        self.calls, self.callbacks = [], 0
        self.short = None
        self.fail_write = self.stop = False
        self.on_current = lambda: None
        self.library = {name: types.SimpleNamespace() for name in ("read", "write")}
        self.functions = {}
        self.abi = types.SimpleNamespace(c=ctypes)
        self.last_errno = 0
        test.enterContext(patch.object(body.os, "getuid", return_value=501))
        test.enterContext(patch.object(body.os, "fstat", side_effect=self.fstat))
        source_stat = os.stat
        def named(path, **options):
            if path == body.NAME:
                test.assertEqual(options, {"dir_fd": 10, "follow_symlinks": False})
                return self.info(self.file_stamp)
            return source_stat(path, **options)  # Source/import metadata only.
        test.enterContext(patch.object(body.os, "stat", side_effect=named))
        source_lstat = Path.lstat
        test.enterContext(patch.object(Path, "lstat", lambda p: self.info(self.parent)
                                      if p == self.path else source_lstat(p)))
        test.enterContext(patch.object(body.os, "lseek", side_effect=self.seek))
        test.enterContext(patch.object(body.os, "fsync", side_effect=self.sync))
        for name in ("open", "close", "dup", "dup2", "pipe", "fork", "execve", "unlink"):
            test.enterContext(patch.object(body.os, name, side_effect=AssertionError("No real body effect")))
        test.enterContext(patch("subprocess.Popen", side_effect=AssertionError("No process in DATA checks")))
        self.owner = native.Acquisition()
        self.owner.grant(threading.current_thread(), self.current)
        self.owner._native, self.owner._native_ready = self, True
        self.parent_lease = self.lease(10, "git_push_directory", os.O_RDONLY)
        self.file_lease = self.lease(11, "git_push_body", os.O_RDWR)
        self.io = body._BodyIO(self.owner, self.parent_lease, self.file_lease, self.path,
                              self.parent, self.original, self.current, _key=body._KEY)

    @staticmethod
    def info(value):
        return types.SimpleNamespace(**dict(zip(("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns",
            "st_ctime_ns", "st_uid", "st_gid", "st_nlink"), value)))

    def lease(self, fd, kind, access):
        # Explicit fake original only. The production issuer/kind validators
        # are unavailable until the separate native/helper hooks are reviewed.
        value = self.owner._new_lease()
        value._publish(fd, self, access, kind)
        value._validated = True
        return value

    def current(self):
        self.callbacks += 1
        self.on_current()
        if self.stop:
            raise wire.WireError("target-changed")

    def fstat(self, fd):
        self.calls.append(("stat", fd))
        if fd == 10:
            return self.info(self.parent)
        assert fd == 11
        return self.info(self.file_stamp)

    def seek(self, fd, offset, whence):
        assert (fd, offset, whence) == (11, 0, os.SEEK_SET)
        self.calls.append(("rewind", fd))
        self.offset = 0
        return 0

    def sync(self, fd):
        assert fd == 11
        self.calls.append(("sync", fd))

    def call(self, name, fd, buffer, maximum):
        assert fd == 11 and name in ("git_push_body_read", "git_push_body_write")
        self.calls.append((name, fd, maximum))
        if name == "git_push_body_read":
            count = min(maximum, len(self.content) - self.offset)
            buffer[:count] = self.content[self.offset:self.offset + count]
            self.offset += count
            return count
        if self.fail_write:
            raise RuntimeError("fixed fake write failure")
        count = maximum if self.short is None else min(maximum, self.short)
        assert self.offset == len(self.content)
        self.content.extend(buffer[:count])
        self.offset += count
        self.tick += 1
        self.file_stamp = (*self.original[:3], len(self.content), self.tick, self.tick, *self.original[6:])
        return count


class GitPushBodyTests(unittest.TestCase):
    def setUp(self):
        self.world = _Returns(self)
        self.request = command()
        self.body = body._PushBody(self.world.io, SELECTED, offered())

    def collect(self, raw=None):
        raw = pack(b"opaque" * 15_000) if raw is None else raw
        self.body.begin(self.request)
        for at in range(0, len(raw), wire.READ_CHUNK):
            self.body.append(raw[at:at + wire.READ_CHUNK])
        return raw

    def refuses(self, function, *args):
        with self.assertRaises(wire.WireError):
            function(*args)

    def test_same_descriptor_seal_readback_and_one_stream_never_store_pack_call_returns(self):
        raw = self.collect()
        digest = self.body.seal()
        self.assertEqual(digest.body_sha256, hashlib.sha256(self.request.raw + raw).hexdigest())
        self.body.claim_send(self.request)
        sent = []
        self.body.send(sent.append, lambda: None)
        self.assertEqual(b"".join(sent), self.request.raw + raw)
        self.assertTrue(all(0 < len(block) <= body.SEND_CHUNK for block in sent))
        self.assertEqual(self.body.phase, "sent")
        self.assertEqual([row for row in self.world.calls if row[0] == "rewind"], [("rewind", 11), ("rewind", 11)])
        native_returns = [row.value for row in self.world.owner._calls
                          if row.name in ("git_push_body_read", "git_push_body_write")]
        self.assertTrue(native_returns and all(type(value) is int for value in native_returns))
        self.assertEqual(self.world.file_lease.state, "OPEN")  # Borrowed, not ours to retire.
        self.refuses(self.body.send, sent.append, lambda: None)

    def test_genuine_short_writes_advance_only_the_returned_bytes(self):
        self.world.short = 3
        raw = self.collect(pack())
        self.assertEqual(bytes(self.world.content), self.request.raw + raw)
        self.assertEqual(self.body.seal().body_bytes, len(self.request.raw) + len(raw))

    def test_partial_write_failure_stays_retained_and_has_no_retry_or_close(self):
        self.body.begin(self.request)
        self.world.fail_write = True
        with self.assertRaises(RuntimeError):
            self.body.append(pack())
        count = len(self.world.calls)
        self.assertTrue(self.body.failed and self.world.io.failed)
        self.refuses(self.body.begin, self.request)
        self.refuses(self.body.seal)
        self.assertEqual(len(self.world.calls), count)
        self.assertEqual(bytes(self.world.content), self.request.raw)
        self.assertEqual(self.world.file_lease.state, "OPEN")

    def test_seal_reads_back_real_buffer_and_refuses_changed_private_bytes(self):
        self.collect(pack())
        self.world.content[-1] ^= 1
        self.refuses(self.body.seal)
        self.assertTrue(self.body.failed)
        self.assertIsNone(self.body.digest)

    def test_parent_or_file_substitution_after_seal_blocks_claim_without_reopen(self):
        self.collect(pack())
        self.body.seal()
        self.world.parent = (self.world.parent[0], 999, *self.world.parent[2:])
        self.refuses(self.body.claim_send, self.request)
        self.assertTrue(self.body.failed)
        self.assertEqual(self.world.file_lease._original_fd, 11)

    def test_equal_command_object_cannot_replace_original_claim_or_repeat_send(self):
        self.collect(pack())
        self.body.seal()
        self.assertEqual(command(), self.request)
        self.refuses(self.body.claim_send, command())
        self.refuses(self.body.claim_send, self.request)
        self.assertEqual(self.body.sent, 0)

    def test_raised_partial_http_write_is_never_replayed(self):
        self.collect()
        self.body.seal()
        self.body.claim_send(self.request)
        attempts = []
        def uncertain(block):
            attempts.append(block[:3])
            raise OSError("fixed fake partial send")
        with self.assertRaises(OSError):
            self.body.send(uncertain, lambda: None)
        self.refuses(self.body.send, uncertain, lambda: None)
        self.assertEqual(len(attempts), 1)
        self.assertTrue(self.body.failed)
        self.assertEqual(self.body.phase, "sending")

    def test_stop_before_write_or_after_actual_send_preserves_first_phase_and_bytes(self):
        self.collect(pack())
        self.body.seal()
        self.body.claim_send(self.request)
        sent = []
        def stop_after(block):
            sent.append(block)
            self.world.stop = True
        self.refuses(self.body.send, stop_after, lambda: None)
        self.assertEqual(b"".join(sent), bytes(self.world.content))
        self.assertEqual(self.body.sent, len(self.world.content))
        self.assertTrue(self.body.failed)
        self.assertNotEqual(self.body.phase, "sent")

    def test_concrete_call_bound_is_sticky_without_further_effects(self):
        self.body.begin(self.request)
        self.world.io.calls = body.IO_CALLS
        before = len(self.world.calls)
        self.refuses(self.body.append, pack())
        self.assertTrue(self.body.failed)
        self.assertEqual(len(self.world.calls), before)
        self.refuses(self.body.seal)


if __name__ == "__main__":
    unittest.main()
