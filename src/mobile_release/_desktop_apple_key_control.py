"""Key-only STOP/custody replies on the ORIGINAL Apple input and writer.

The single zero byte is STOP, never an ACK/GO. Only the already generated
private body may finish its custody exchange under the original cleanup cut.
No helper, pending consent, provider request or new deadline can use that tail.
"""
from __future__ import annotations

import os
import select
import time

from . import _desktop_apple_key_protocol as wire
from . import apple_provisioning_api as api


class _PendingStopped(KeyboardInterrupt):
    """The exact standalone pre-ACK marker, never an arbitrary interruption."""


def _operation(source):
    from ._desktop_apple_provisioning_control import AppleProvisioningInput
    from .desktop_apple_provisioning import AppleProvisioningRun
    wire.need(type(source) is AppleProvisioningInput)
    operation = source.require_operation()
    wire.need(type(operation) is AppleProvisioningRun and operation.source is source
              and operation.request is source.initial and operation.request.context["mode"] == "key-prepare"
              and source.engine is not None and source.engine.input is source
              and not source.close_claimed and source.fd is not None and not source.custody_unknown)
    return operation


def _identity(source):
    observed = os.fstat(source.fd)
    wire.need((observed.st_dev, observed.st_ino, observed.st_mode) == source.identity)


def _unknown(source, error):
    source.custody_unknown = True
    source._key_ack_lost = True
    source.guard._abort(error)


def _stop_marker(source, *, line_started=False):
    # A marker is permitted only BETWEEN the two fixed reply records. It
    # cannot repair a truncated ACK or be repeated to refresh first failure.
    wire.need(not line_started and not source._key_stop_seen)
    source._key_stop_seen = True
    source.stop("cancelled")


def poll_active(source, guard):
    """Return true only for the new mode's original idle one-byte STOP poll."""
    if (source.initial is None or source.initial.context["mode"] != "key-prepare"
            or not source.active or source.material_pending or source.reading or source.close_claimed):
        return False
    source._owner()
    wire.need(guard is source.guard)
    if source.stop_reason != "none":
        guard.cancelled = True
        return True
    try:
        _operation(source)
        if time.monotonic() >= source.work_end:
            source.stop("timed-out")
            return True
        source._clock()
        _identity(source)
        wire.need(not source.buffer)
        try:
            value = os.read(source.fd, 1)
        except BlockingIOError:
            return True
        if value == b"":
            source._key_pipe_eof = True
            source.stop("cancelled")
        elif value == wire.STOP:
            _stop_marker(source)
        else:
            raise wire.common.ProtocolError()
    except BaseException as error:
        source.stop("cancelled")
        _unknown(source, error)
    return True


def tail_endpoint(source):
    # This is the SAME W/H and original first-F, not a new ten-second window.
    return min(source.work_end + 10, source.hard_endpoint())


def tail_point(source):
    operation = _operation(source)
    from ._desktop_apple_key_private import KeyOutput
    output = operation._key_output
    wire.need(type(output) is KeyOutput and output._operation is operation
              and output._engine is source.engine and output._request is source.initial
              and operation._request_bytes == operation._request_data()
              and not operation._close_claimed and not source._key_ack_lost and not source._key_pipe_eof
              and not source._key_body_failed
              and not source.guard.lifetime_ledger.fatal and source.guard.handler_state != "UNKNOWN")
    source.guard._check_owner()
    wire.need(source.raw_clock is not None)
    raw = time.clock_gettime_ns(source.raw_clock)
    wire.need(type(raw) is int and 0 < raw < source.raw_hard_end)
    if raw >= source.raw_work_end or time.monotonic() >= source.work_end:
        source.stop("timed-out")
    wire.need(source.stop_reason in {"none", "cancelled", "timed-out"}
              and time.monotonic() < tail_endpoint(source))
    _identity(source)


def returned_runtime_check(source, runtime, primary):
    """Close one already-returned generator scope without renewing work.

    This is not ``runtime.check`` for another command. It can only finish the
    exact command-six context whose retained original C/A/W result already
    contains the complete private frame. Later native custody/save authority
    still requires the original receiver, source, vault and all real joins.
    """
    if source is None or source.initial is None or source.initial.context["mode"] != "key-prepare":
        return False
    operation = _operation(source)
    # The inner context sees its body exception before the outer command
    # manager does. Record it first; a later STOP must never hide an ordinary
    # body/decode error merely because a valid frame was also captured.
    if primary is not None and not isinstance(primary, KeyboardInterrupt):
        source._key_body_failed = True
        operation.remember(primary)
        return False
    if (source.stop_reason not in {"cancelled", "timed-out"} or source._key_body_failed
            or operation.primary is not None and not isinstance(operation.primary, KeyboardInterrupt)):
        return False
    from ._desktop_apple_distribution_key import AppleDistributionKeyWork
    from ._store_runtime import StoreRuntimeContext
    from .build_inputs import FiniteScratch
    child = operation._distribution_key
    wire.need(type(runtime) is StoreRuntimeContext and operation.runtime is runtime
              and type(child) is AppleDistributionKeyWork and child._operation is operation
              and child._source is source and child._runtime is runtime and child._mode == "key-prepare"
              and child._started and child._claimed and not child._retired and not child._command_active
              and operation._pending == 6 and operation._next_command == 7 and operation._command_claimed
              and operation._pending_argv == ("bundle", "exec", "ruby",
                  str(runtime.tooling_root / "fastlane/apple_distribution_key.rb"))
              and source.reply_step == 1 and source._ack_consumed and wire.common.sha(source._pending_ack)
              and child._pending_ack == source._pending_ack and child._slot is not None
              and child._frame is not None and child._parts is not None and len(child._parts) == 3)
    outcome = child._outcome()
    wire.need(outcome is not None and outcome.no_target is None and outcome.result_integrity == "complete"
              and outcome.returncode == 0 and child._slot._engine.decoded is not None
              and child._slot._engine.decoded[0] is child._frame and child._slot._engine.decoded[1] == b""
              and all(part.obj is child._frame for part in child._parts))
    tail_point(source)
    # cleanup=True alone checks only process/thread. These fixed original
    # active/reservation checks are also necessary: retired Home/Invocation
    # objects cannot be borrowed, even to finish an old command scope.
    wire.need(runtime._invocation is operation.invocation and type(runtime._home) is FiniteScratch
              and runtime._home.layout == "online-runner" and runtime._home.cancellation is operation.guard
              and operation.scratches and operation.scratches[0] is runtime._home
              and runtime._home.active and not runtime._home.claimed)
    runtime._invocation._apple_key_returned_runtime(operation)
    runtime._home._owner(cleanup=True)
    runtime._home._check()
    runtime._check_interpreters()
    tail_point(source)
    return True


def _read_reply(source, *, tail):
    line = bytearray()
    try:
        while not line.endswith(b"\n"):
            wire.need(len(line) < wire.common.ACK_LIMIT)
            if tail:
                tail_point(source)
                if source.buffer:
                    value = bytes(source.buffer[:1])
                    source.buffer[:1] = b"\0"
                    del source.buffer[:1]
                else:
                    try:
                        value = os.read(source.fd, 1)
                    except BlockingIOError:
                        select.select([source.fd], [], [], min(.05, max(0, tail_endpoint(source) - time.monotonic())))
                        continue
                    if not value:
                        source._key_pipe_eof = True
                        raise wire.common.ProtocolError()
            else:
                value = bytes(source._take(1, audit=False))
            if value == wire.STOP:
                _stop_marker(source, line_started=bool(line))
                if not tail:
                    # Native abandon_pending sends only this marker and never
                    # enters its ACK writer. Do not poison known cancellation,
                    # but do not repair partial/repeated/trailing reply data.
                    wire.need(not source.buffer)
                    _identity(source)
                    try:
                        trailing = os.read(source.fd, 1)
                    except BlockingIOError:
                        trailing = None
                    if trailing:
                        source.buffer.extend(trailing)
                        raise wire.common.ProtocolError()
                    if trailing == b"":
                        source._key_pipe_eof = True
                    # This does not mint NeverGenerated: the native parent
                    # still needs its own never-entered ACK and real joins.
                    raise _PendingStopped()
                continue
            line.extend(value)
        return bytes(line)
    finally:
        line[:] = b"\0" * len(line)


def pending(source, payload):
    operation = _operation(source)
    wire.validate_event(source.initial, "key-pending", payload, 1)
    operation.checkpoint()
    wire.need(source.reply_step == 0 and not source.reading and not source.material_pending
              and not source.material_receiving and not source.buffer and source._pending_ack is None)
    source.reply_step = 1  # consumed before first write, including a lost ACK.
    source.reading = source.material_pending = source.material_receiving = True
    source.read_remaining = 1
    try:
        source.engine.provisioning_event("key-pending", payload)
        revision, digest = wire.reply(_read_reply(source, tail=False), source.initial, 1,
            api.digest(api.canonical(payload["update"])))
        wire.need(revision == source._revision + 1 and not source.buffer and not source._key_stop_seen)
        source.reading = source.material_pending = source.material_receiving = False
        operation.checkpoint()
        source._revision, source._pending_ack = revision, digest
        return digest
    except _PendingStopped:
        raise  # This one internal marker is cancellation, never ACK/GO.
    except BaseException as error:
        _unknown(source, error)
        raise
    finally:
        source.reading = source.material_receiving = source.material_pending = False
        source.read_remaining = 0


def consume_pending(source, operation, child):
    from ._desktop_apple_distribution_key import AppleDistributionKeyWork
    wire.need(operation is _operation(source) and type(child) is AppleDistributionKeyWork
              and operation._distribution_key is child and child._operation is operation
              and not source._ack_attempted)
    source._ack_attempted = True
    wire.need(source.reply_step == 1 and not source.reading and not source.material_pending
              and not source._ack_consumed and wire.common.sha(source._pending_ack)
              and operation.plan == wire.expected_plan(operation.request))
    operation.checkpoint()
    source._ack_consumed = True
    return source._pending_ack


def transfer(source, output):
    """One body exchange; only the native receiver owns the retained copy."""
    operation = _operation(source)
    from ._desktop_apple_key_private import KeyOutput
    wire.need(type(output) is KeyOutput and operation._key_output is output and output._operation is operation
              and source.reply_step == 1 and source._ack_consumed and wire.common.sha(source._pending_ack)
              and not source.reading and not source.material_pending and not source.material_receiving and not source.buffer)
    metadata = output.metadata()
    wire.validate_event(source.initial, "key-output", metadata, 2)
    source.reply_step = 2
    source.reading = source.material_pending = source.material_receiving = source._key_tail_writing = True
    source.read_remaining = 1
    try:
        tail_point(source)
        source.engine.provisioning_event("key-output", metadata)
        output.write_body()
        revision, digest = wire.reply(_read_reply(source, tail=True), source.initial, 2, api.digest(api.canonical(metadata)))
        wire.need(revision == source._revision + 1 and not source.buffer)
        tail_point(source)
        source._revision = revision
        source._key_retained_ack = (revision, digest)
        output.accept_custody(source._key_retained_ack)
    except BaseException as error:
        _unknown(source, error)
        raise
    finally:
        source.reading = source.material_receiving = source.material_pending = source._key_tail_writing = False
        source.read_remaining = 0


def not_generated(source, output, *, commands, before_command):
    operation = _operation(source)
    wire.need(operation._key_output is output and output._operation is operation
              and source.reply_step == 1 and not source._key_ack_lost and not source.reading
              and not source.material_pending and not source.buffer)
    value = {"commands": commands, "beforeCommand": before_command}
    wire.validate_event(source.initial, "key-not-generated", value, 2)
    source.reply_step = 2
    source._key_tail_writing = True
    try:
        tail_point(source)
        source.engine.provisioning_event("key-not-generated", value)
    finally:
        source._key_tail_writing = False
