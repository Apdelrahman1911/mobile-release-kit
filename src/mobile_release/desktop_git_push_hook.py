"""Fixed pre-push comparison on the SAME borrowed command FD8.

Stock Git invokes this exact source-held hook, then closes its input before
waiting. Review only compares. Apply waits for the original parent's durable
candidate ACK. Neither reply is a token, HTTP send, successful Push or join.
No named socket, second process owner, stdout payload or dynamic hook exists.
"""
from __future__ import annotations

import math
from pathlib import Path
import time

from . import desktop_git_remote_helper as original
from . import _git_push_private_protocol as private
from . import git_push_transport as transport

SOCKET_CALLS = 256
PIPE_CALLS = 256
WORKING_RESERVE = 512 * 1024  # Within Push's separate 16MiB, never extra implicit quota.
_RETAINED = []


class _SocketIO(original._SocketIO):
    def call(self, name, *args, roots=()):
        transport.require(self.count < SOCKET_CALLS, "response-limit")
        return super().call(name, *args, roots=roots)


class _PipeIO(original._PipeIO):
    def _call(self, name, lease, maximum):
        transport.require(self.count < PIPE_CALLS, "response-limit")
        return super()._call(name, lease, maximum)


class _Entry(original._Entry):
    binding_type = private.Clock
    pipe_io_type = _PipeIO

    def __init__(self, mode, clock, review_digest, remote, url, runtime_dir, started, *, kind="push"):
        super().__init__(remote, url, runtime_dir, started)
        self.mode, self.context, self.review_digest, self.kind = mode, clock, review_digest, kind
        self.hook = None
        self.input_eof = self.reply_entered = self.reply_returned = False

    def current(self):
        self.origin()
        transport.require(not self.failed and not self.closed and not self.return_entered
                          and time.monotonic() < self.work_end,
                          "cancelled" if self.failed else "network-unavailable")
        # The hook is the sole FD8 reader for this phase. No advisory STOP
        # read may consume part of its ACK. EOF is checked by _private_read;
        # the unchanged C/A/W also signals STOP to the entire original tree.

    def acquire(self):
        self.origin(); transport.require(not self.entered)
        self.entered = True
        transport.require(type(self.started) in (int, float) and math.isfinite(self.started)
                          and isinstance(self.runtime_dir, Path) and self.runtime_dir.is_absolute()
                          and self.mode in ("review", "apply") and type(self.context) is private.Clock
                          and self.kind in ("push", "push-new-branch"))
        private._hex(self.review_digest)
        self.current()
        self._bridge(self.context)  # Same native raw endpoints, not hook-launch +45/+55.
        self.current()
        self.io = _SocketIO.__new__(_SocketIO)
        _SocketIO.__init__(self.io, self.acquisition)
        self.endpoint = original._BorrowedEndpoint(self)
        self.endpoint.check()
        self._acquire_pipes()

    def run(self):
        transport.require(self.entered and self.binding is self.context and self.hook is None
                          and not self.input_eof and not self.reply_entered)
        line = bytearray()
        while True:
            self.current()
            block = self.pipe_io.read(1025 - len(line))
            transport.require(type(block) is bytes and len(block) <= 1025 - len(line))
            self.current()
            if not block:
                self.input_eof = True
                break
            line.extend(block)
            transport.require(len(line) <= 1024 and line.count(b"\n") <= 1
                              and (b"\n" not in line or line.endswith(b"\n")), "response-limit")
        self.hook = private.Hook(self.context, self.mode, self.review_digest, self.remote, self.url, bytes(line), self.kind)
        self.current(); self.endpoint.check()
        self.reply_entered = True  # Before writing the request; never replay after a lost ACK.
        self._private_write(self.hook.request())
        self.hook.accept_reply(self._private_read())
        self.reply_returned = True
        self.current()

    def complete(self):
        self.origin()
        transport.require(not self.return_entered and self.pipes_close_entered)
        self.return_entered = True
        # No extra private frame and no claim that these local closes joined
        # the parent or the helper. Only genuine known local completion lets
        # stock Git continue; the original C/A/W still owns all descendants.
        return 0 if (self.primary is None and not self.unknown and self.closed
                     and self.input_eof and self.reply_returned) else 74


def main(*, mode, clock, review_digest, remote, url, runtime_dir, started, kind="push"):
    entry = _Entry(mode, clock, review_digest, remote, url, runtime_dir, started, kind=kind)
    try:
        try:
            entry.acquire()
            entry.run()
        except BaseException as error:
            entry.remember(error)
        finally:
            entry.close_pipes()
        return entry.complete()
    except BaseException as error:
        entry.remember(error)
        return 74
    finally:
        if entry.unknown or not entry.closed:
            _RETAINED.append(entry)
