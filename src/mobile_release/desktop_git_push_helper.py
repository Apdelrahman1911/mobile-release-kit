"""Closed Push helper facet of the existing inherited GitRemote entry.

Same Acquisition, ordinary pipes, borrowed FD8, native clock and one-attempt
close implementation. The private body has two additional original leases;
neither pathname nor body digest authorizes their acquisition or a POST.
"""
from __future__ import annotations

import hashlib
import math
import os
from pathlib import Path
import time

from . import desktop_git_remote_helper as original
from . import _git_push_private_protocol as private
from . import _github_connection_transport as http
from . import git_push_body as bodies
from . import git_push_transport as transport
from . import git_remote_control as controls
from ._desktop_git_push_helper import _Helper, _ReviewHelper

_RETAINED = []


class _Entry(original._Entry):
    binding_type = private.Binding

    def __init__(self, remote, url, runtime_dir, started):
        super().__init__(remote, url, runtime_dir, started)
        self.body_parent = self.body_file = self.body_io = None
        self.send_entered = self.send_returned = False
        self.monitor_stop = False

    def current(self):
        self.origin()
        transport.require(not self.failed and not self.closed and not self.return_entered
                          and time.monotonic() < self.work_end, "cancelled" if self.failed else "network-unavailable")
        # While stock Git runs the fixed pre-push hook, that hook alone may
        # read its reply on inherited FD8. Never steal one byte of its ACK.
        # The original C/A/W still delivers STOP to this whole command tree.
        if self.monitor_stop:
            transport.require(self.io.receive(self.endpoint, 1) is None, "cancelled")

    def http_failure(self, reason):
        self.remember(transport.PushError(reason if reason in transport._REASONS else "cleanup-unknown"))

    def _open_body(self):
        binding = self.binding
        transport.require(type(binding) is private.Binding and binding.mode == "apply"
                          and self.body_parent is self.body_file is self.body_io is None)
        self.current()
        acquisition, runtime = self.acquisition, self.io.runtime
        # Retain BOTH genuine routes before either open or validation. They
        # remain the same original Acquisition's finite lease roster.
        self.body_parent, self.body_file = acquisition._new_lease(), acquisition._new_lease()
        for lease, access, kind in ((self.body_parent, os.O_RDONLY, "git_push_directory"),
                                    (self.body_file, os.O_RDWR, "git_push_body")):
            try:
                self.current()
                lease._state = "ACQUIRING"
                flags = access | os.O_CLOEXEC | os.O_NOFOLLOW
                if kind == "git_push_directory":
                    flags |= os.O_DIRECTORY
                    def open_original():
                        return os.open(binding.path, flags)
                else:
                    def open_original():
                        return os.open(bodies.NAME, flags, dir_fd=self.body_parent.fileno())
                descriptor = acquisition._invoke("git_push_original_open", open_original, roots=(self, lease))
                transport.require(type(descriptor) is int and 2 < descriptor < (1 << 31))
                lease._publish_known(descriptor, runtime, access, kind)
                acquisition._check_origin()
                lease._validate()
                expected = binding.parent_stamp if kind == "git_push_directory" else binding.body_stamp
                observed = acquisition._invoke("git_push_original_stat", os.fstat, descriptor,
                                               roots=(self, lease), mutating=False)
                transport.require(bodies._stamp(observed) == expected)
                self.current()
            except BaseException as error:
                acquisition._record_error(error)
                if lease.state == "ACQUIRING":
                    lease._state = "UNKNOWN"
                    acquisition._remember("git_push_original_publication", error)
                raise
        self.body_io = bodies._BodyIO.__new__(bodies._BodyIO)
        bodies._BodyIO.__init__(self.body_io, acquisition, self.body_parent, self.body_file, binding.path,
            binding.parent_stamp, binding.body_stamp, self._current_callback, _key=bodies._KEY)

    def acquire(self):
        self.origin(); transport.require(not self.entered)
        self.entered = True
        transport.require(type(self.started) in (int, float) and math.isfinite(self.started)
                          and isinstance(self.runtime_dir, Path) and self.runtime_dir.is_absolute()
                          and type(self.remote) is type(self.url) is str and len(self.remote) <= 256
                          and self.remote == "mrk::" + self.url and self.url.startswith("https://github.com/")
                          and self.url.endswith(".git") and self.url.isascii() and len(self.url) <= 251)
        self.current()
        self.io = original._SocketIO.__new__(original._SocketIO)
        original._SocketIO.__init__(self.io, self.acquisition)
        self.endpoint = original._BorrowedEndpoint(self)
        self.endpoint.check()
        binding = private.challenge(self._private_read())
        transport.require(binding.identity == self.endpoint.identity
                          and self.url == "https://github.com/" + binding.target.repository + ".git")
        self._bridge(binding)
        self.current()
        self._acquire_pipes()
        if binding.mode == "apply":
            self._open_body()
        self.get_entered = True
        self._private_write(binding.request())
        token = binding.accept_grant(self._private_read())
        self.get_returned = True
        try:
            self.current()
            started = math.nextafter(self.work_end - transport.WORK_SECONDS, -math.inf)
            self.budget = http._Budget(started, monotonic=self.clock, _profile=http._ExchangeProfile.GIT_PUSH)
            self.budget.end = min(self.budget.end, self.work_end)
            self.transport = transport._make_transport(binding.target, binding.mode, token, started=started,
                runtime_dir=str(self.runtime_dir), budget=self.budget, current=self._current_callback,
                failure=self._failure_callback)
        finally:
            token = None
        if binding.mode == "review":
            self.helper = _ReviewHelper(self.transport, read=self.pipe_io.read, write=self.pipe_io.write,
                                        current=self._current_callback)
        else:
            self.helper = _Helper(self.transport, self.body_io, read=self.pipe_io.read, write=self.pipe_io.write,
                                  current=self._current_callback, send_point=self.send_point)

    def send_point(self, request, digest):
        transport.require(self.binding.mode == "apply" and not self.send_entered and not self.monitor_stop
                          and type(self.helper) is _Helper and self.helper.pack_eof
                          and self.helper.body.io is self.body_io and self.helper.body.digest == digest
                          and self.helper.request is request and self.helper.body.phase == "sealed")
        self.send_entered = True
        self.current(); self.endpoint.check()
        self._private_write(self.binding.send(digest, self.helper.body.sealed_stamp))
        reply = self._private_read()
        transport.require(reply == self.binding.send_reply(digest))
        self.send_returned = self.monitor_stop = True
        self.current()

    def close_pipes(self):
        self.origin()
        transport.require(not self.pipes_close_entered)
        for lease in (self.body_file, self.body_parent):
            if lease is not None:
                try:
                    transport.require(time.monotonic() < self.hard_end, "network-unavailable")
                    lease.close()
                except BaseException as error:
                    self.unknown = True
                    self.remember(error)
        super().close_pipes()
        self.closed &= all(lease is None or lease.state == "CLOSED" for lease in (self.body_file, self.body_parent))
        self.unknown |= not self.closed
        if self.body_io is not None and getattr(self.body_io, "buffer", None) is not None:
            self.body_io.buffer[:] = b"\0" * bodies.SEND_CHUNK

    def complete(self):
        self.origin()
        transport.require(not self.return_entered and type(self.binding) is private.Binding and self.get_returned
                          and self.pipes_close_entered)
        self.return_entered = True
        if self.unknown or not self.closed:
            state, reason = "unknown", "cleanup-unknown"
        elif self.primary is None and self.helper is not None and self.helper.finished:
            state, reason = "ok", None
        else:
            state = "refused"
            if self.primary is None:
                self.remember(transport.PushError())
            observed = getattr(self.primary, "reason", "response-invalid")
            reason = observed if observed in transport._REASONS - {"cleanup-unknown"} else "response-invalid"
        remote = self.transport
        control = controls.empty() if remote is None else remote.control
        if state == "refused":
            control = controls.refusal(control, reason)
        before = None if remote is None or remote.offered is None else hashlib.sha256(remote.offered.raw).hexdigest()
        response = None if remote is None or remote.posted is None else remote.posted.value
        after = None if remote is None or remote.readback is None else hashlib.sha256(remote.readback.raw).hexdigest()
        self._private_write(self.binding.returned(state, reason,
            first_failure_ns=None if state == "ok" else self.first_failure_ns,
            cleanup_end_ns=self.binding.hard_end_ns if state == "ok" else self.cleanup_end_ns,
            control=control, advertisement_sha256=before, response=response, after_sha256=after), cleanup=True)
        return 0 if state == "ok" else 70


def main(*, remote, url, runtime_dir, started):
    entry = _Entry(remote, url, runtime_dir, started)
    try:
        try:
            entry.acquire()
            entry.helper.run()
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
