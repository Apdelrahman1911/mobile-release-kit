"""Two fixed LOCAL P12 replies on the original Apple input/output owners.

The first ACK is this operation's durable local intent, not a provider-send
permission. The second means native raw-body custody only, never NEW/readback
or finality. There is no retry, audit-after-failure work or renewed deadline.
"""
from . import _desktop_apple_p12_protocol as wire
from . import apple_provisioning_api as api


def exchange(source, kind, payload):
    from ._desktop_apple_provisioning_control import AppleProvisioningInput
    from ._desktop_apple_p12_worker import P12Steps
    wire.need(type(source) is AppleProvisioningInput and source.initial.context["mode"] == "p12-save")
    operation = source.require_operation()
    steps = operation._p12_steps
    wire.need(type(steps) is P12Steps and steps.operation is operation)
    sequence = source.reply_step + 1
    wire.validate_event(source.initial, kind, payload, sequence)
    operation.checkpoint()
    wire.need(not source.reading and not source.material_pending and not source.material_receiving
              and not source.buffer and source.engine is not None)
    steps.admit_exchange(kind, payload)
    source.reply_step = sequence
    source.reading = source.material_pending = source.material_receiving = True
    source.read_remaining = 1
    original = api.canonical(payload)
    line = bytearray()
    try:
        if kind == "p12-output":
            operation._p12_output.begin_transfer()
        source.engine.provisioning_event(kind, payload)
        if kind == "p12-output":
            operation._p12_output.write_body()
        while not line.endswith(b"\n"):
            wire.need(len(line) < wire.common.ACK_LIMIT)
            line.extend(source._take(1, audit=False))
        wire.need(original == api.canonical(payload) and not source.buffer)
        result, digest = wire.reply(bytes(line), source.initial, kind, sequence, payload)
        if kind == "p12-pending":
            wire.need(result["revision"] == source._revision + 1 and source._pending_ack is None)
            source._revision = result["revision"]
            source._pending_ack = digest
        source.reading = source.material_pending = source.material_receiving = False
        operation.checkpoint()
        steps.accept_exchange(kind, payload, result, digest)
        return result, digest
    except BaseException as error:
        # An unknown/partial reply never becomes absence or a new intent. The
        # original input retains custody flags until its real close path.
        operation.remember(error)
        raise
    finally:
        line[:] = b"\0" * len(line)
        source.reading = source.material_receiving = False
        source.read_remaining = 0


def consume_pending(source, operation, child):
    from ._desktop_apple_p12_assembly import P12AssemblyWork
    source._owner()
    wire.need(not source._ack_attempted)
    source._ack_attempted = True
    steps = operation._p12_steps
    wire.need(operation is source.require_operation() and operation.request.context["mode"] == "p12-save"
              and type(child) is P12AssemblyWork and operation._p12_assembly is child
              and steps is not None and steps.pending_returned and steps.pending_payload is not None
              and steps.pending_ack is source._pending_ack and wire.common.sha(source._pending_ack)
              and source.reply_step == 4 and not source.reading and not source.material_pending
              and not source._ack_consumed and operation.plan is None and operation.attempt is None)
    steps.current_selection()
    operation.checkpoint()
    source._ack_consumed = True
    return source._pending_ack
