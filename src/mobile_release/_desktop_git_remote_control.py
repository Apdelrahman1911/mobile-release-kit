"""One GitRemote facet of the existing held SavedCommandInput.

This adds only one private GO token and one candidate/keep ACK phase. The
original input, cancellation ledger, command C/A/W and close routes remain the
owners. Tokens are never returned through ordinary/public result frames.
"""
from __future__ import annotations

import math
import os
import select
import time

from . import _desktop_git_remote_protocol as wire
from . import git_remote_control as controls
from ._desktop_saved_command_control import SavedCommandDomain, _SavedCommandInput


class GitRemoteInput(_SavedCommandInput):
    def __init__(self, started):
        super().__init__(started, domain=SavedCommandDomain.GitRemote)
        self.hard_end = started + wire.FINALITY_SECONDS
        self.initial = self.operation = self.channel = None
        self.ready_sent = self.go_returned = False
        self.candidate_claimed = self.candidate_waiting = self.candidate_returned = False
        self.candidate = self.ack_revision = self.keep = None
        self.first_failure_ns = self.cleanup_end_ns = None
        self.http_control = controls.empty()
        self._token = None
        self._token_consumed = self._polling = False

    def __repr__(self):
        return "<original private GitRemote input>"

    def _frame(self, maximum):
        self._owner()
        wire.require(self.guard is not None and (not self.active or self.candidate_waiting)
                     and maximum in (wire.REQUEST_LIMIT, wire.GO_LIMIT, wire.ACK_LIMIT))
        while True:
            self.guard.check()
            wire.require(len(self.buffer) <= maximum)
            if b"\n" in self.buffer:
                raw = bytes(self.buffer)
                wire.require(raw.endswith(b"\n") and raw.count(b"\n") == 1)
                self.buffer.clear()
                return raw
            wire.require(self.fd is not None)
            select.select([self.fd], [], [], min(0.05, max(0.0, self.work_end - time.monotonic())))

    def request(self):
        wire.require(self.initial is None and not self.request_returned)
        request = wire.parse_request(self._frame(wire.REQUEST_LIMIT))
        raw_clock = getattr(time, "CLOCK_UPTIME_RAW", None)
        wire.require(type(raw_clock) is int)
        before, now = time.monotonic(), time.clock_gettime_ns(raw_clock)
        wire.require(type(now) is int and 0 <= now < request.work_end_ns < request.hard_end_ns)
        # Same original lower-bound bridge; neither GET/POST nor a later child
        # receives a new operation budget at its launch.
        self.work_end = min(self.work_end, math.nextafter(before + (request.work_end_ns - now) / 1e9, -math.inf))
        self.hard_end = min(self.hard_end, math.nextafter(before + (request.hard_end_ns - now) / 1e9, -math.inf))
        self.cleanup_end_ns = request.hard_end_ns
        self.initial, self.request_returned = request, True
        self.guard.check()
        return request

    def failure_observed(self):
        self._owner()
        if self.first_failure is not None:
            return
        self.first_failure = time.monotonic()
        self.hard_end = min(self.hard_end, self.first_failure + 10)
        raw_clock = getattr(time, "CLOCK_UPTIME_RAW", None)
        raw = time.clock_gettime_ns(raw_clock) if type(raw_clock) is int else None
        after = time.monotonic()
        if type(raw) is int:
            raw -= math.ceil(max(0.0, after - self.first_failure) * 1_000_000_000)
        if self.initial is not None and type(raw) is int and 0 < raw < self.initial.hard_end_ns:
            self.first_failure_ns = raw
            self.cleanup_end_ns = min(self.initial.hard_end_ns, raw + 10_000_000_000)

    def helper_returned(self, channel, value):
        """Merge this original helper's earlier F, never receipt-time renew it."""
        from ._git_remote_private_protocol import Returned
        from ._desktop_git_push_control import GitPushInput
        if type(self) is GitPushInput:
            from ._git_push_private_protocol import Returned
        self._owner()
        wire.require(channel is self.channel and channel.source is self and channel.helper_return is value
                     and type(value) is Returned and self.initial is not None
                     and channel.binding.digest == self.initial.digest
                     and channel.binding.work_end_ns == self.initial.work_end_ns
                     and channel.binding.hard_end_ns == self.initial.hard_end_ns
                     and (self.first_failure is None or self.first_failure_ns is not None))
        raw_clock = getattr(time, "CLOCK_UPTIME_RAW", None)
        wire.require(type(raw_clock) is int)
        before, raw = time.monotonic(), time.clock_gettime_ns(raw_clock)
        wire.require(type(raw) is int and 0 < raw < self.initial.hard_end_ns)
        if value.first_failure_ns is None:
            wire.require(value.status == "ok" and value.cleanup_end_ns == self.initial.hard_end_ns)
            self.http_control = controls.merge(self.http_control, value.control)
            return  # Cannot clear a parent failure or expand its shorter cutoff.
        first = value.first_failure_ns
        wire.require(max(1, self.initial.work_end_ns - 45_000_000_000) <= first <= raw
                     and value.cleanup_end_ns == min(self.initial.hard_end_ns, first + 10_000_000_000))
        self.http_control = controls.merge(self.http_control, value.control)
        mapped = math.nextafter(before + (first - raw) / 1e9, -math.inf)
        self.first_failure = mapped if self.first_failure is None else min(self.first_failure, mapped)
        self.first_failure_ns = first if self.first_failure_ns is None else min(self.first_failure_ns, first)
        cutoff = min(self.cleanup_end_ns or self.initial.hard_end_ns, self.initial.hard_end_ns,
                     value.cleanup_end_ns, self.first_failure_ns + 10_000_000_000)
        self.cleanup_end_ns = cutoff
        self.hard_end = min(self.hard_end, self.first_failure + 10,
                           math.nextafter(before + (cutoff - raw) / 1e9, -math.inf))
        wire.require(time.monotonic() < self.hard_end)

    def _poll_control_only(self, guard):
        self._owner()
        wire.require(guard is self.guard)
        if self.stop_reason != "none" or self.close_claimed:
            if self.stop_reason != "none":
                guard.cancelled = True
            return
        if time.monotonic() >= min(self.work_end, self.hard_end):
            self.stop("timed-out")
            return
        active = self.active and not self.candidate_waiting
        if active and self.buffer:
            self.stop()
            return
        try:
            wire.require(self.fd is not None)
            current = os.fstat(self.fd)
            if (current.st_dev, current.st_ino, current.st_mode) != self.identity:
                self.custody_unknown = True
                raise wire.ProtocolError("The original private Git input changed.")
            maximum = (wire.REQUEST_LIMIT if not self.request_returned else
                       wire.ACK_LIMIT if self.candidate_waiting else wire.GO_LIMIT)
            limit = 1 if active else min(4096, maximum + 1 - len(self.buffer))
            wire.require(limit > 0)
            try:
                chunk = os.read(self.fd, limit)
            except BlockingIOError:
                return
            if not chunk or active:
                self.stop()
                return
            self.buffer.extend(chunk)
            if len(self.buffer) > maximum:
                self.stop()
        except BaseException as error:
            self.stop()
            guard._abort(error)

    def poll(self, guard):
        # Nested currentness checks still see native STOP/EOF. They do not
        # recursively enter the private socket broker or grant a second token.
        self._poll_control_only(guard)
        if self._polling or self.channel is None or self.channel.closed:
            return
        self._polling = True
        try:
            self.channel.poll()
        finally:
            self._polling = False

    def bind_operation(self, operation):
        from .desktop_git_remote import GitRemoteOperation
        self._owner()
        wire.require(type(operation) is GitRemoteOperation and self.operation is None
                     and operation.source is self and operation.request is self.initial
                     and operation.guard is self.guard and self.guard is not None
                     and self.guard._saved_command_input() is self and self.request_returned and not self.ready_sent)
        self.operation = operation

    def require_operation(self):
        from .desktop_git_remote import GitRemoteOperation
        self._owner()
        wire.require(type(self.operation) is GitRemoteOperation and self.operation.source is self
                     and self.operation.request is self.initial and self.operation.guard is self.guard)
        return self.operation

    def ready(self):
        self._owner()
        wire.require(not self.ready_sent and not self.active)
        self.require_operation().source_post(hash_files=True)
        self.guard.check()
        wire.require(not self.buffer)
        self.ready_sent = True
        return wire.ready(self.initial)

    def go(self):
        self._owner()
        wire.require(self.ready_sent and not self.go_returned)
        raw = self._frame(wire.GO_LIMIT)
        self.go_returned = self.active = True  # Before parsing/consuming.
        self._token = wire.private_go(self.initial, raw)
        raw = None
        self.require_operation().source_post(hash_files=True)
        self.guard.check()

    @property
    def credential_channel(self):
        from ._git_remote_input_channel import OriginalInputChannel
        operation = self.require_operation()
        wire.require(type(self.channel) is OriginalInputChannel and self.channel.source is self
                     and operation.network_pending and operation.pending is not None)
        return self.channel.command

    def take_helper_token(self, channel):
        self._owner()
        wire.require(channel is self.channel and self.go_returned and not self._token_consumed
                     and self._token is not None and channel.get_entered)
        self._token_consumed = True
        self.require_operation().credential_current(channel)
        self.guard.check()
        result, self._token = self._token, None
        return result

    def handoff(self, sent):
        self._owner()
        operation = self.require_operation()
        wire.require(self.go_returned and self.active and not self.candidate_claimed and not self.buffer
                     and self.initial.phase == "apply" and operation.pending is None and operation.remote_returned
                     and self.channel is not None and self.channel.closed and self.channel.get_sent
                     and type(sent) is wire.Candidate and sent.request is self.initial)
        self.guard.check()
        self.candidate_claimed = self.candidate_waiting = True
        self.candidate = sent
        try:
            operation.write_candidate(sent)
            revision, keep = wire.acknowledged(self.initial, sent, self._frame(wire.ACK_LIMIT))
            self.candidate_waiting = False
            self.guard.check()  # STOP after ACK still forbids every publication.
            operation.source_post(hash_files=True)
            self.ack_revision, self.keep, self.candidate_returned = revision, keep, True
            return keep
        except BaseException:
            self.failure_observed()
            raise

    def remaining_timeout(self, timeout):
        self._owner()
        wire.require(type(timeout) is int and 0 < timeout <= wire.COMMAND_SECONDS)
        self.guard.check()
        remaining = int(self.work_end - time.monotonic())
        wire.require(remaining >= 1)
        return min(timeout, remaining)

    def command_limits(self, timeout, capture, output_limit):
        operation = self.require_operation()
        pending = operation.pending
        wire.require(self.go_returned and self.active and not self.candidate_waiting
                     and operation.entered and pending is not None and pending.claimed
                     and capture is True and output_limit == pending.output_limit
                     and timeout <= (45 if operation.network_pending else 10))
        return self.remaining_timeout(timeout), output_limit

    def close(self):
        # Python private copies are bounded, not claimed end-to-end zeroized.
        self._token = None
        return super().close()
