"""Closed Push phases on the SAME GitRemote SavedCommandInput/FD8 owner.

The inherited poll/STOP/frame/close and failure-clock implementations remain
original. The fixed hook can request exactly one candidate while that original
command is pending; it cannot authorize another command or reset its clock.
"""
from __future__ import annotations

import math
import time

from . import _desktop_git_push_protocol as wire
from ._desktop_git_remote_control import GitRemoteInput
from ._git_push_input_channel import PushInputChannel
from . import git_push_transaction as transaction


class GitPushInput(GitRemoteInput):
    def __repr__(self):
        return "<original private Git Push input>"

    def request(self):
        wire.require(self.initial is None and not self.request_returned)
        request = wire.parse_request(self._frame(wire.REQUEST_LIMIT))
        raw_clock = getattr(time, "CLOCK_UPTIME_RAW", None)
        wire.require(type(raw_clock) is int)
        before, now = time.monotonic(), time.clock_gettime_ns(raw_clock)
        wire.require(type(now) is int and 0 <= now < request.work_end_ns < request.hard_end_ns)
        self.work_end = min(self.work_end, math.nextafter(before + (request.work_end_ns - now) / 1e9, -math.inf))
        self.hard_end = min(self.hard_end, math.nextafter(before + (request.hard_end_ns - now) / 1e9, -math.inf))
        self.cleanup_end_ns = request.hard_end_ns
        self.initial, self.request_returned = request, True
        self.guard.check()
        return request

    def bind_operation(self, operation):
        from .desktop_git_push import GitPushOperation
        self._owner()
        wire.require(type(operation) is GitPushOperation and self.operation is None
                     and operation.source is self and operation.request is self.initial
                     and operation.guard is self.guard and self.guard is not None
                     and self.guard._saved_command_input() is self and self.request_returned and not self.ready_sent)
        self.operation = operation

    def require_operation(self):
        from .desktop_git_push import GitPushOperation
        self._owner()
        wire.require(type(self.operation) is GitPushOperation and self.operation.source is self
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
        self.go_returned = self.active = True
        self._token = wire.private_go(self.initial, raw)
        raw = None
        self.require_operation().source_post(hash_files=True)
        self.guard.check()

    @property
    def credential_channel(self):
        operation = self.require_operation()
        wire.require(type(self.channel) is PushInputChannel and self.channel.source is self
                     and operation.network_pending and operation.pending is not None)
        return self.channel.command

    def handoff(self, sent):
        self._owner()
        operation, channel = self.require_operation(), self.channel
        tx = operation.repository._transaction
        wire.require(self.go_returned and self.active and not self.candidate_claimed and not self.buffer
                     and self.initial.phase == "apply" and operation.pending is not None and operation.pending.claimed
                     and operation.network_pending and operation.remote_entered and not operation.remote_returned
                     and type(channel) is PushInputChannel and not channel.closed and channel.get_sent
                     and channel.command is not None and channel.command._exported
                     and channel.polling and self._polling and channel.hook_entered and not channel.hook_returned
                     and not channel.send_entered and type(tx) is transaction.PushTransaction and tx.running
                     and tx.hook_entered and tx.ack_entered and not tx.acknowledged
                     and type(sent) is wire.Candidate and sent.request is self.initial and sent.intent is tx.intent)
        self.guard.check()
        self.candidate_claimed = self.candidate_waiting = True
        self.candidate = sent
        try:
            operation.write_candidate(sent)
            revision = wire.acknowledged(self.initial, sent, self._frame(wire.ACK_LIMIT))
            self.candidate_waiting = False
            self.guard.check()  # STOP after durable ACK still forbids pack send/POST.
            operation.source_post(hash_files=True)
            self.ack_revision, self.candidate_returned = revision, True
        except BaseException:
            self.failure_observed()
            raise
