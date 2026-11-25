"""Profile-only dialogue borrowed from the original Apple input/STOP owner."""
from __future__ import annotations

from . import _desktop_apple_profile_protocol as wire
from . import apple_provisioning_api as api


def exchange(source, kind, payload):
    from ._desktop_apple_provisioning_control import AppleProvisioningInput
    wire.need(type(source) is AppleProvisioningInput and source.initial.context["mode"] in wire.MODES)
    operation = source.require_operation()
    sequence = source.reply_step + 1
    wire.validate_event(source.initial, kind, payload, sequence)
    audit = sequence > 2
    source.audit_point() if audit else operation.checkpoint()
    wire.need(not source.reading and not source.material_pending and not source.material_receiving and not source.buffer
              and source.engine is not None and sequence <= wire.MAX_EVENTS)
    if sequence > 1:
        operation._profile.identity_current(audit=audit)
    else:
        wire.need(kind == "identity" and source._profile_identity is None)
    # Slot consumption precedes output: missing/wrong/replayed replies cannot
    # make this original phase available again, or become a journal ACK.
    source.reply_step = sequence
    source.reading = source.material_pending = source.material_receiving = True
    source.read_remaining = 1
    source.audit_writing = audit
    captured = api.canonical(payload)
    line = bytearray()
    try:
        source.engine.provisioning_event(kind, payload)
        while not line.endswith(b"\n"):
            wire.need(len(line) < wire.common.ACK_LIMIT)
            line.extend(source._take(1, audit=audit))
        wire.need(captured == api.canonical(payload))
        if sequence == 1:
            result = wire.identity_reply(bytes(line), source.initial, payload)
        else:
            revision, result = wire.journal_reply(bytes(line), source.initial, sequence, payload["update"])
            wire.need(revision == source._revision + 1)
        wire.need(not source.buffer)
        source.reading = source.material_receiving = source.material_pending = False
        source.audit_point() if audit else operation.checkpoint()
        if sequence == 1:
            wire.need(source._profile_identity is None)
            source._profile_identity = result
        else:
            source._revision = revision
            if sequence == 2:
                wire.need(source._pending_ack is None)
                source._pending_ack = result
    except BaseException as error:
        # ProvisioningAttempt deliberately catches a failed persist so the
        # account remains fenced. Preserve this SAME original input failure as
        # well: a rejected/lost ACK is not a healthy completed worker result.
        operation.remember(error)
        raise
    finally:
        line[:] = b"\0" * len(line)
        source.reading = source.material_receiving = source.audit_writing = False
        source.read_remaining = 0
    source.audit_point() if audit else operation.checkpoint()
    return result


def consume_pending(source, operation, request):
    source._owner()
    wire.need(not source._ack_attempted)
    source._ack_attempted = True
    wire.need(operation is source.require_operation() and operation.plan is not None
              and operation.request.context["mode"] == "profile-create" and operation.plan.action == "create_profile"
              and request == operation.plan.request and source.reply_step == 2 and wire.common.sha(source._pending_ack)
              and not source.reading and not source.material_pending and not source._ack_consumed)
    operation._profile.identity_current()
    operation.checkpoint()
    source._ack_consumed = True
    return source._pending_ack
