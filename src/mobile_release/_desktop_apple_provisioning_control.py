"""Bundle-ID journal ACKs on the SAME saved-command input/STOP owner.

No new pipe, task, filesystem journal or callback registration lives here.
Only the exact new domain may borrow the original Store P8 material reader.
An ACK is comparison DATA sent by the original native job AFTER durable CAS
and its actual join; receiving these bytes cannot create that native fact.
"""
from __future__ import annotations

import math
import os
import select
import time

from . import _desktop_apple_provisioning_protocol as wire
from . import apple_provisioning_api as api
from ._desktop_saved_command_control import SavedCommandDomain, _SavedCommandInput
from ._desktop_store_preflight_control import StorePreflightInput


class AppleProvisioningInput(_SavedCommandInput):
    def __init__(self, started):
        super().__init__(started, domain=SavedCommandDomain.AppleProvisioning)
        self.initial = self.operation = self.engine = None
        self.material_pending = self.material_receiving = self._material_read = False
        self._material = None
        self._profile_material = self._profile_parts = None
        self.reply_step = self.read_remaining = 0
        self.reading = self.audit_writing = False
        self.raw_clock = self.raw_work_end = self.raw_hard_end = None
        self.hard_end = started + wire.FINALITY_SECONDS
        self._revision = self._pending_ack = self._profile_identity = None
        self._ack_attempted = self._ack_consumed = False

    def _bind_engine(self, engine):
        from ._desktop_apple_provisioning_engine import _Engine
        self._owner()
        self._require(type(engine) is _Engine and engine.input is self and self.engine is None)
        self.engine = engine

    _request_material = StorePreflightInput._request_material
    def receive_material(self, operation, scratch):
        from .apple_provisioning_signing import MODES
        if operation.request.context["mode"] in MODES:
            from ._desktop_apple_profile_private import receive_material
            return receive_material(self, operation, scratch)
        return StorePreflightInput.receive_material(self, operation, scratch)

    def profile_material(self, operation):
        from ._desktop_apple_profile_private import profile_material
        return profile_material(self, operation)

    def request(self):
        request = super().request()
        self.initial = request  # Retained before the first native-clock read.
        self._revision = request.native["journalRevision"]
        clock = getattr(time, "CLOCK_UPTIME_RAW", None)
        self._require(type(clock) is int)
        before = time.monotonic()
        raw = time.clock_gettime_ns(clock)
        work, hard = (int(request.native["clock"][name]) for name in ("workEndNs", "hardEndNs"))
        self._require(0 < raw < work < hard)
        self.raw_clock, self.raw_work_end, self.raw_hard_end = clock, work, hard
        # Native A/W/H includes queue/admission/material wait. Child startup
        # may tighten it, never start another 1200-second operation.
        self.work_end = min(self.work_end, math.nextafter(before + (work - raw) / 1e9, -math.inf))
        self.hard_end = min(self.hard_end, math.nextafter(before + (hard - raw) / 1e9, -math.inf))
        self.guard.check()
        return request

    def bind_operation(self, operation):
        from .desktop_apple_provisioning import AppleProvisioningRun
        self._owner()
        self._require(type(operation) is AppleProvisioningRun and self.operation is None
                      and operation.source is self and operation.guard is self.guard and operation.request is self.initial
                      and self.guard._saved_command_input() is self and self.active and self.request_returned
                      and not self.close_claimed)
        self.operation = operation

    def require_operation(self):
        from .desktop_apple_provisioning import AppleProvisioningRun
        self._owner()
        self._require(type(self.operation) is AppleProvisioningRun and self.operation.source is self
                      and self.operation.guard is self.guard and self.operation.request is self.initial)
        self.guard._check_owner()
        return self.operation

    def _clock(self, *, terminal=False):
        self._owner()
        if self.raw_clock is not None:
            raw = time.clock_gettime_ns(self.raw_clock)
            self._require(type(raw) is int and raw > 0)
            if raw >= self.raw_work_end and not terminal:
                self.stop("timed-out")
            self._require(raw < (self.raw_hard_end if terminal else self.raw_work_end))

    def poll(self, guard):
        self._require(guard is self.guard)
        if not self.close_claimed and self.raw_clock is not None:
            try:
                self._clock()
            except BaseException as error:
                self.stop("timed-out")
                # An actual clock/custody exception is not a successful STOP.
                if not isinstance(error, wire.ProtocolError):
                    guard._abort(error)
        super().poll(guard)

    def hard_endpoint(self):
        self._owner()
        return min(self.hard_end, self.first_failure + 10) if self.first_failure is not None else self.hard_end

    def audit_endpoint(self):
        return min(self.work_end, self.hard_endpoint())

    def audit_point(self):
        """Only the already-armed attempt may report under original F/W/H."""
        operation = self.require_operation()
        self._require(self.initial.context["mode"] in {"register", "profile-reuse", "profile-create"} and self._pending_ack is not None
                      and not operation._close_claimed and operation._request_bytes == operation._request_data()
                      and not self.custody_unknown and not self.guard.lifetime_ledger.fatal
                      and self.guard.handler_state != "UNKNOWN" and self.fd is not None and not self.close_claimed)
        self._clock()
        self._require(time.monotonic() < self.audit_endpoint())
        value = os.fstat(self.fd)
        if (value.st_dev, value.st_ino, value.st_mode) != self.identity:
            self.custody_unknown = True
            error = wire.ProtocolError()
            self.guard._abort(error)
            raise error

    def output_checkpoint(self, *, terminal):
        # Called only by the existing engine's exact Apple domain branch. No
        # other domain/event can use the audit-only guard bypass.
        if terminal:
            self._owner(); self._clock(terminal=True)
            self._require(time.monotonic() < self.hard_endpoint())
        elif self.audit_writing:
            self._require(self.reading and (3 if self.initial.context["mode"] in wire.PROFILE_MODES else 2)
                          <= self.reply_step <= wire.max_events(self.initial.context["mode"]))
            self.audit_point()
        else:
            self.guard.check(); self._clock()
            self._require(self.first_failure is None)

    def _take(self, count, *, audit):
        result = bytearray()
        try:
            while len(result) < count:
                self.read_remaining = count - len(result)
                if audit:
                    self.audit_point()
                    if not self.buffer:
                        try:
                            value = os.read(self.fd, self.read_remaining)
                        except BlockingIOError:
                            value = None
                        if value is not None:
                            self._require(bool(value)); self.buffer.extend(value)
                else:
                    self.guard.check(); self._clock()
                    self._require(self.first_failure is None)
                if self.buffer:
                    length = min(len(self.buffer), count - len(result))
                    result.extend(self.buffer[:length])
                    self.buffer[:length] = b"\0" * length
                    del self.buffer[:length]
                else:
                    end = self.audit_endpoint() if audit else self.work_end
                    select.select([self.fd], [], [], min(.05, max(0, end - time.monotonic())))
            return result
        except BaseException:
            result[:] = b"\0" * len(result)
            raise
        finally:
            self.read_remaining = 0

    def exchange(self, kind, payload):
        if self.initial.context["mode"] in wire.PROFILE_MODES:
            from ._desktop_apple_profile_control import exchange
            return exchange(self, kind, payload)
        operation = self.require_operation()
        sequence = self.reply_step + 1
        wire.validate_event(self.initial, kind, payload, sequence)
        audit = sequence > 1
        self.audit_point() if audit else operation.checkpoint()
        self._require(not self.reading and not self.material_pending and not self.material_receiving and not self.buffer
                      and sequence <= wire.MAX_EVENTS and self.engine is not None)
        # The event slot is consumed BEFORE writing: failure/lost ACK never
        # permits a repeat, and even a late matching ACK cannot renew consent.
        self.reply_step = sequence
        self.reading = self.material_pending = self.material_receiving = True
        self.read_remaining = 1
        self.audit_writing = audit
        line = bytearray()
        try:
            self.engine.provisioning_event(kind, payload)
            while not line.endswith(b"\n"):
                self._require(len(line) < wire.ACK_LIMIT)
                line.extend(self._take(1, audit=audit))
            revision, ack = wire.reply(bytes(line), self.initial, sequence, api.digest(api.canonical(payload["update"])))
            self._require(revision == self._revision + 1 and not self.buffer)
            # The bounded reply reader is over BEFORE an ordinary guard poll:
            # there is no remaining read slot, and any following byte is STOP.
            self.reading = self.material_receiving = self.material_pending = False
            self.audit_point() if audit else operation.checkpoint()
            self._revision = revision
            if sequence == 1:
                self._pending_ack = ack
        finally:
            line[:] = b"\0" * len(line)
            self.reading = self.material_receiving = self.audit_writing = False
            self.read_remaining = 0
        operation.checkpoint() if not audit else self.audit_point()
        return ack

    def consume_pending_ack(self, operation, request):
        if self.initial.context["mode"] in wire.PROFILE_MODES:
            from ._desktop_apple_profile_control import consume_pending
            return consume_pending(self, operation, request)
        self._owner()
        self._require(not self._ack_attempted)
        self._ack_attempted = True  # Foreign or expired consumption is final.
        self._require(operation is self.require_operation() and operation.plan is not None
                      and request == operation.plan.request and operation.request.context["mode"] == "register"
                      and self.reply_step == 1 and wire.sha(self._pending_ack) and not self.reading
                      and not self.material_pending and not self._ack_consumed)
        operation.checkpoint()
        self._ack_consumed = True
        return self._pending_ack

    def close(self):
        # The exact base's one-attempt FD close; StorePreflightInput.close uses
        # its own zero-argument super and cannot be borrowed across domains.
        super().close()
        if self.operation is not None:
            self._require(self.operation.closed())
        self.buffer[:] = b"\0" * len(self.buffer)
        self.buffer.clear()
        self._material = None  # No process-wide secure-erasure claim.
        self._profile_material = self._profile_parts = None

    def material_closed(self):
        return (StorePreflightInput.material_closed(self)
                and self._profile_material is None and self._profile_parts is None)
