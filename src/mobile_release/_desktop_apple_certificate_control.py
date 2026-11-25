"""Certificate phases on ONE existing reader/writer; every lost ACK refuses.

Only journal updates already armed may use the old original audit cut. Native
identity/policy replies do not grant a new GO, reset failure or refresh W/H.
"""
from . import _desktop_apple_certificate_protocol as wire
from . import apple_provisioning_api as api


def bind_post_command_slot(operation, engine, slot):
    """Retain only this original POST slot, BEFORE its C/A/W acquisition."""
    if (operation.request.context["mode"] != "certificate-create"
            or operation._wire_request is None or operation._wire_request.method != "POST"):
        return
    from ._command_process import CommandOutcomeSlot, _Outer
    from .apple_provisioning_certificate_issuance import CertificateCreationAttempt
    from ._desktop_apple_certificate_worker import CertificateSteps
    steps, source = operation._certificate, operation.source
    ledger = operation.guard.lifetime_ledger
    wire.need(type(steps) is CertificateSteps and steps.operation is operation and steps._post_original is None
              and steps._phase == "posted" and steps.pending_returned and not steps._body_failed
              and type(operation.attempt) is CertificateCreationAttempt and operation.attempt.plan is operation.plan
              and operation._wire_request is operation.plan.request and operation.plan.action == "create_certificate"
              and source._ack_consumed and wire.common.sha(source._pending_ack)
              and source.require_operation() is operation and operation._command_claimed
              and type(operation._pending) is int and 10 <= operation._pending <= 13
              and operation._next_command == operation._pending + 1
              and tuple(operation._pending_argv) == steps.helper_argv()
              and type(slot) is CommandOutcomeSlot and type(engine) is _Outer and slot._engine is engine
              and engine.slot is slot and engine.guard is operation.guard and engine.scope is None
              and engine.binding is None and engine.owns is False and engine.evidence is None
              and engine._store_timing is None and engine.text is False and ledger._command is slot
              and ledger._commands == operation._pending)
    # Original object identities, not another command/result owner. Keep the
    # slot after aggregate ledger folding; an old count/receipt is insufficient.
    steps._post_original = (slot, ledger, operation._pending, operation.runtime, operation.invocation,
        operation.runtime._home, operation._wire_runner, operation._wire_request, operation.plan,
        operation.attempt, source._pending_ack, source._certificate_material)


def _returned_post(steps):
    from ._desktop_ios_signed_operation import original_outcome
    op = steps.operation
    wire.need(steps._post_original is not None)
    slot, ledger, index, runtime, invocation, home, runner, request, plan, attempt, ack, material = steps._post_original
    wire.need(op._certificate is steps and op.source.require_operation() is op
              and op.request.context["mode"] == "certificate-create" and op.request is op.source.initial
              and op.runtime is runtime and op.invocation is invocation and runtime._home is home
              and op._wire_runner is runner and op._wire_request is request and op.plan is plan and op.attempt is attempt
              and request is plan.request and request.method == "POST" and plan.action == "create_certificate"
              and attempt.plan is plan and attempt._entered and attempt._action_gate.locked()
              and attempt.record.possible_send and attempt.record.context == op.context
              and attempt.record.plan_sha256 == plan.sha256 and op._pending == index
              and op._next_command == index + 1 and op._command_claimed and op._pending_capture is True
              and op._pending_argv == steps.helper_argv() and steps._phase == "posted"
              and op.source._ack_consumed and op.source._pending_ack == ack
              and op.source._certificate_material is material and material is not None
              and ledger is op.guard.lifetime_ledger)
    verdict = ledger.verdict()
    outcome = original_outcome(slot, op.guard, None, None)
    wire.need(outcome is not None and outcome.no_target is None and outcome.result_integrity == "complete"
              and outcome.returncode == 0 and verdict.cleanup_complete and verdict.contained
              and not verdict.fatal and verdict.commands == index + 1 and verdict.profile_calls == 0
              and slot._engine.decoded is not None and slot._engine.decoded[1] == b"")
    return slot._engine.decoded[0]


def capture_returned_post(steps, completed):
    """Bind the actual returned bytes before parsing the sparse 201 receipt."""
    raw = _returned_post(steps)
    wire.need(steps._post_raw is None and type(raw) is bytes and raw is completed.stdout
              and completed.returncode == 0 and completed.stderr == b"")
    steps._post_raw = raw


def returned_post_runtime_check(source, runtime, primary):
    """Close this returned POST observation, NOT authorize any later work.

    The ordinary guard still raises STOP after the context closes. Only the
    existing already-armed journal audit may preserve the receipt afterward.
    No current-key/permission refresh, new command or cleanup clock is minted.
    """
    if source is None or source.initial is None or source.initial.context["mode"] != "certificate-create":
        return False
    op = source.require_operation()
    steps = op._certificate
    if steps is None or op._wire_request is None or op._wire_request.method != "POST":
        return False
    if primary is not None and not isinstance(primary, KeyboardInterrupt):
        steps._body_failed = True
        op.remember(primary)  # Before the fallible outer context exit can observe STOP.
        return False
    if (source.stop_reason not in {"cancelled", "timed-out"} or steps._body_failed
            or op.primary is not None and not isinstance(op.primary, KeyboardInterrupt)):
        return False
    from ._store_runtime import StoreRuntimeContext
    from .build_inputs import FiniteScratch
    wire.need(type(runtime) is StoreRuntimeContext and op.runtime is runtime and not op._close_claimed
              and source.engine is not None and source.engine.input is source and source.active
              and not source.close_claimed and not source.reading and not source.material_pending
              and not source.material_receiving and not source.buffer and not source.custody_unknown
              and source.first_failure is not None and source.guard.handler_state != "UNKNOWN"
              and op._request_bytes == op._request_data() and steps._post_raw is not None
              and _returned_post(steps) is steps._post_raw and steps._post_response is not None
              and steps._post_response.status == 201 and steps._post_response.settled is True
              and steps._post_retained is not None and steps._post_retained is op.attempt.receipt
              and not op.attempt._receipt_conflict)
    # audit_point checks the actual held input FD, raw W/H, first-F and original
    # min(W, F+10, H). It does NOT poll/refresh a work or provider permission.
    source.audit_point()
    home, runner = runtime._home, op._wire_runner
    wire.need(type(home) is FiniteScratch and type(runner) is FiniteScratch and home is not runner
              and home.layout == runner.layout == "online-runner"
              and home.cancellation is runner.cancellation is op.guard
              and op.scratches and op.scratches[0] is home and op.scratches[-1] is runner
              and home.active and not home.claimed and runner.active and not runner.claimed)
    runtime._invocation._apple_certificate_returned_runtime(op)
    for original in (home, runner):
        original._owner(cleanup=True)
        original._check()
    runtime._check_interpreters()
    source.audit_point()
    return True


def exchange(source, kind, payload):
    from ._desktop_apple_provisioning_control import AppleProvisioningInput
    wire.need(type(source) is AppleProvisioningInput and (source.initial.context["mode"] in wire.MODES
              or source.initial.context["mode"] in wire.common.P12_MODES
              and kind in {"certificate-key", "certificate-identities", "certificate-policy"}))
    operation = source.require_operation()
    steps = operation._certificate
    wire.need(steps is not None)
    sequence = source.reply_step + 1
    wire.validate_event(source.initial, kind, payload, sequence)
    audit = kind == "certificate-attempt"
    source.audit_point() if audit else operation.checkpoint()
    wire.need(not source.reading and not source.material_pending and not source.material_receiving
              and not source.buffer and source.engine is not None and sequence <= wire.EVENTS)
    steps.admit_exchange(kind, payload)  # Exact retained per-kind order, no caller-chosen renewal.
    source.reply_step = sequence
    source.reading = source.material_pending = source.material_receiving = True
    source.audit_writing = audit
    source.read_remaining = 1
    original = api.canonical(payload)
    line = bytearray()
    try:
        source.engine.provisioning_event(kind, payload)
        while not line.endswith(b"\n"):
            wire.need(len(line) < wire.common.ACK_LIMIT)
            line.extend(source._take(1, audit=audit))
        wire.need(original == api.canonical(payload) and not source.buffer)
        result, digest = wire.reply(bytes(line), source.initial, sequence, kind, payload)
        if kind == "certificate-attempt" and result["stopped"]:
            # Same native writer's audit-only tail. Latch before any later
            # work checkpoint; false on a later ACK never clears an existing
            # STOP/first failure. Receiving a journal ACK is not GET consent.
            source.stop("cancelled")
        if kind in {"certificate-pending", "certificate-attempt"}:
            wire.need(result["revision"] == source._revision + 1)
            source._revision = result["revision"]
            if kind == "certificate-pending":
                wire.need(source._pending_ack is None)
                source._pending_ack = digest
        source.reading = source.material_receiving = source.material_pending = False
        source.audit_point() if audit else operation.checkpoint()
        steps.accept_exchange(kind, payload, result, digest)
        return result, digest
    except BaseException as error:
        operation.remember(error)
        raise
    finally:
        line[:] = b"\0" * len(line)
        source.reading = source.material_receiving = source.audit_writing = False
        source.read_remaining = 0


def consume_pending(source, operation, request):
    source._owner()
    wire.need(not source._ack_attempted)
    source._ack_attempted = True
    wire.need(operation is source.require_operation() and operation.request.context["mode"] == "certificate-create"
              and operation._certificate is not None and operation._certificate.pending_returned
              and operation.plan is not None and operation.plan.action == "create_certificate" and request == operation.plan.request
              and wire.common.sha(source._pending_ack) and not source.reading and not source.material_pending and not source._ack_consumed)
    operation._certificate.current_key(require_history=True)
    operation.checkpoint()
    source._ack_consumed = True
    return source._pending_ack
