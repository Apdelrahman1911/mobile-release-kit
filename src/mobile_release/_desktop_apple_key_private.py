"""Generated-key transfer using the SAME Apple stdout/input owners.

The native ACK means body-complete custody only. Native EOF/joins, vault NEW,
full readback, journal final CAS and private drain remain later original cuts.
No generated key can be replaced by an empty-on-cancellation profile trailer.
"""
from __future__ import annotations

import hashlib
import os
import select
import struct
import time

from . import _desktop_apple_key_protocol as wire
from . import _desktop_apple_key_control as control
from . import apple_provisioning_api as api
from ._desktop_apple_distribution_key import AppleDistributionKeyWork, PREPARE_MODE, PRIVATE_LIMIT, _parts

MAGIC = b"MRK-APPLE-KEY-TRANSFER/1\n"
HEADER = struct.Struct(">I32s32s")
TRANSFER_LIMIT = len(MAGIC) + HEADER.size + PRIVATE_LIMIT


def header(request_sha256, frame):
    wire.need(wire.common.sha(request_sha256))
    _parts(frame, public=False)
    return MAGIC + HEADER.pack(len(frame), bytes.fromhex(request_sha256), hashlib.sha256(frame).digest())


class KeyOutput:
    __slots__ = ("_operation", "_engine", "_request", "_child", "_frame", "_metadata", "_header",
                 "_claimed", "_body_done", "_bytes", "_ack", "_never_generated", "_worker_retired", "_closed")

    def __init__(self, operation):
        from .desktop_apple_provisioning import AppleProvisioningRun
        from ._desktop_apple_provisioning_engine import _Engine
        wire.need(type(operation) is AppleProvisioningRun and operation.source.require_operation() is operation
                  and operation.request.context["mode"] == PREPARE_MODE and type(operation.source.engine) is _Engine
                  and operation._key_output is None)
        self._operation, self._engine, self._request = operation, operation.source.engine, operation.request
        self._child = self._frame = self._metadata = self._header = self._ack = None
        self._claimed = self._body_done = self._never_generated = self._worker_retired = self._closed = False
        self._bytes = 0
        operation._key_output = self  # Before any generator/private capture.

    def __repr__(self):
        return "<KeyOutput private>"

    def _binding(self):
        operation = self._operation
        wire.need(operation._key_output is self and operation.source.require_operation() is operation
                  and operation.source.engine is self._engine and operation.request is self._request
                  and operation.request.context["mode"] == PREPARE_MODE and not self._closed)
        return operation

    def retain_returned(self, child):
        operation = self._binding()
        wire.need(type(child) is AppleDistributionKeyWork and child is operation._distribution_key
                  and child._operation is operation and child._source is operation.source
                  and child._runtime is operation.runtime and child._mode == PREPARE_MODE
                  and not child._retired and not child._command_active and self._child is None and not self._claimed)
        self._child = child  # Retain exact original before any fallible check.
        outcome = child._outcome()
        wire.need(outcome is not None and outcome.no_target is None and outcome.result_integrity == "complete"
                  and outcome.returncode == 0 and child._scratch_closed() and child._frame is not None
                  and child._slot._engine.decoded is not None and child._slot._engine.decoded[0] is child._frame
                  and child._slot._engine.decoded[1] == b"" and child._parts is not None)
        self._frame = child._frame
        parts = _parts(self._frame, public=False)
        wire.need(len(parts) == 3 and all(left == right for left, right in zip(parts, child._parts)))
        self._metadata = {"frameBytes": len(self._frame), "frameSha256": api.digest(self._frame),
            "csrSha256": hashlib.sha256(parts[1]).hexdigest(), "publicKeySha256": hashlib.sha256(parts[2]).hexdigest()}
        wire.output_metadata(self._metadata)
        self._header = header(self._request.digest, self._frame)

    def metadata(self):
        self._binding()
        wire.need(self._metadata is not None and self._frame is not None and not self._claimed)
        return dict(self._metadata)

    def _write(self, data):
        view = memoryview(data)
        while view:
            control.tail_point(self._operation.source)
            engine = self._engine
            wire.need(not engine.terminal_claimed and engine.output.owned and engine.output.number == 1
                      and not engine.output.close_claimed)
            observed = os.fstat(1)
            wire.need((observed.st_dev, observed.st_ino, observed.st_mode) == engine.output.identity)
            try:
                count = os.write(1, view[:4096])
            except BlockingIOError:
                select.select([], [1], [], min(.05, max(0, control.tail_endpoint(self._operation.source) - time.monotonic())))
                continue
            wire.need(type(count) is int and 0 < count <= min(4096, len(view)))
            self._bytes += count
            wire.need(self._bytes <= TRANSFER_LIMIT)
            engine.output_bytes += count
            view = view[count:]

    def write_body(self):
        self._binding()
        wire.need(not self._claimed and self._frame is not None and self._header is not None
                  and self._operation.source._key_tail_writing and self._operation.source.reply_step == 2)
        self._claimed = True  # Includes every partial/lost write.
        self._write(self._header)
        self._write(self._frame)
        self._body_done = True

    def accept_custody(self, ack):
        self._binding()
        wire.need(self._claimed and self._body_done and self._ack is None
                  and type(ack) is tuple and len(ack) == 2 and type(ack[0]) is int
                  and ack[0] > 0 and ack[1] == api.digest(api.canonical(self._metadata))
                  and self._operation.source._key_retained_ack is ack)
        self._ack = ack  # This cannot set a keySaved/ref/CSR result.

    def report_never_generated(self, child):
        operation = self._binding()
        wire.need(not self._claimed and self._frame is None and self._metadata is None and self._child is None)
        if child is None:
            wire.need(operation._distribution_key is None and operation._next_command == 6)
            before = True
        else:
            wire.need(type(child) is AppleDistributionKeyWork and child is operation._distribution_key
                      and child._operation is operation and child._mode == PREPARE_MODE
                      and child._never_generated() and not child._command_active)
            wire.need(child._scratch_closed() or child._scratch is None and not child._claimed)
            self._child = child
            before = not child._claimed
        verdict = operation.guard.lifetime_ledger.verdict()
        wire.need(verdict.cleanup_complete and verdict.contained and verdict.profile_calls == 0)
        self._never_generated = True
        if operation.source.reply_step == 1:
            control.not_generated(operation.source, self, commands=verdict.commands, before_command=before)

    def retire_worker(self):
        """Transfer reference ownership, not a secure-erasure or save claim."""
        operation = self._binding()
        wire.need(operation._close_claimed and operation._pending is None)
        if self._worker_retired:
            wire.need(self.worker_closed() and (operation._distribution_key is None
                      or operation._distribution_key.private_closed()))
            return  # The original close is repeat-observed, never repeated.
        verdict = operation.guard.lifetime_ledger.verdict()
        wire.need(verdict.cleanup_complete and verdict.contained and verdict.profile_calls == 0)
        child = self._child if self._child is not None else operation._distribution_key
        if self._frame is not None:
            wire.need(type(child) is AppleDistributionKeyWork and self._ack is not None
                      and self._ack is operation.source._key_retained_ack and self._body_done
                      and child._frame is self._frame and child._scratch_closed() and child._outcome() is not None)
            # SAME native receiver retained this exact body before its ACK.
            # Only worker copies are released here; the native body remains
            # rooted until actual NEW/readback/final-CAS/all-jobs retirement.
            child._material = child._private_input = child._result = child._frame = child._parts = child._slot = None
            child._retired = True
        elif child is not None:
            wire.need(type(child) is AppleDistributionKeyWork and child._never_generated())
            child.retire_non_generated(operation)
        else:
            wire.need(not self._claimed and operation._next_command <= 6)
        self._frame = self._header = self._child = None
        self._worker_retired = True

    def worker_closed(self):
        return self._worker_retired and self._frame is None and self._header is None and self._child is None

    def retire(self, engine):
        wire.need(engine is self._engine and engine.service is self._operation and engine.request is self._request
                  and engine.input is self._operation.source and engine.input.material_closed()
                  and all(slot.owned and slot.closed for slot in (engine.output, engine.error_output))
                  and not engine.guard.lifetime_ledger.fatal and self.worker_closed())
        if self._closed:
            return
        self._metadata = self._ack = None
        self._closed = True

    def closed(self):
        return self._closed and self.worker_closed() and self._metadata is None and self._ack is None
