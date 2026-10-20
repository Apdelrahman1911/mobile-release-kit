"""Fixed key producer/verifier child of the ORIGINAL AppleProvisioningRun.

There is no second runner, stdin API, transport, clock or journal here. The
parent must extend its closed v3 command/material/ACK branches before calling
this child. Generated output is PRIVATE; it has no byte/public-CSR getter and
cannot use profile's empty-on-cancellation trailer or ordinary no-save cleanup.
The same original CommandOutcomeSlot is retained before command acquisition,
including when a late STOP prevents run_owned returning a CompletedProcess.
"""
from __future__ import annotations

import base64
import binascii
import struct
import sys

from .apple_provisioning_api import ProvisioningError
from .build_inputs import FiniteScratch, finite_scratch
from .owned_process import run_owned


PREPARE_MODE = "key-prepare"
VERIFY_MODES = frozenset(("key-recover", "certificate-review", "certificate-create", "certificate-reconcile"))
MODES = VERIFY_MODES | {PREPARE_MODE}
MAGIC = b"MRK-APPLE-DISTRIBUTION-KEY/1\n"
PUBLIC_MAGIC = b"MRK-APPLE-DISTRIBUTION-KEY-PUBLIC/1\n"
KEY_LIMIT, CSR_LIMIT, SPKI_LIMIT = 3072, 4096, 1024
PRIVATE_LIMIT = len(MAGIC) + 12 + KEY_LIMIT + CSR_LIMIT + SPKI_LIMIT
PUBLIC_LIMIT = len(PUBLIC_MAGIC) + 8 + CSR_LIMIT + SPKI_LIMIT
LAYOUT = "apple-distribution-key"


def _need(condition):
    if not condition:
        raise ProvisioningError("apple_distribution_key_refused")


def _parts(raw, *, public):
    """Bounds/framing DATA, not PKCS8/CSR validation or native key custody."""
    magic, bounds = (PUBLIC_MAGIC, (CSR_LIMIT, SPKI_LIMIT)) if public else (MAGIC, (KEY_LIMIT, CSR_LIMIT, SPKI_LIMIT))
    maximum = PUBLIC_LIMIT if public else PRIVATE_LIMIT
    header = len(magic) + 4 * len(bounds)
    _need(type(raw) is bytes and header < len(raw) <= maximum and raw.startswith(magic))
    lengths = struct.unpack_from(">" + "I" * len(bounds), raw, len(magic))
    _need(all(0 < length <= limit for length, limit in zip(lengths, bounds)) and header + sum(lengths) == len(raw))
    offset, parts = header, []
    for length in lengths:
        # Views of the one retained original capture, not private output copies.
        parts.append(memoryview(raw)[offset:offset + length])
        offset += length
    csr = parts[0 if public else 1]
    _need(bytes(csr).startswith(b"-----BEGIN CERTIFICATE REQUEST-----\n") and
          bytes(csr).endswith(b"-----END CERTIFICATE REQUEST-----\n") and all(byte < 128 for byte in csr))
    return tuple(parts)


def _decoded(value, limit):
    _need(type(value) is bytes and 0 < len(value) <= 4 * ((limit + 2) // 3) and value.isascii())
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ProvisioningError("apple_distribution_key_refused") from None
    _need(0 < len(raw) <= limit and base64.b64encode(raw) == value)
    return raw


def _stored_frame(material):
    """Three exact borrowed native fields; a backup restore grants no ACK."""
    _need(type(material) is tuple and len(material) == 3 and all(type(part) is bytes for part in material))
    private, csr, public = material
    _need(0 < len(csr) <= CSR_LIMIT)
    private, public = _decoded(private, KEY_LIMIT), _decoded(public, SPKI_LIMIT)
    frame = MAGIC + struct.pack(">III", len(private), len(csr), len(public)) + private + csr + public
    _parts(frame, public=False)
    return frame


def bind_original_command_slot(operation, engine, slot):
    """Fixed _Outer constructor hook, after its fields but BEFORE acquire.

    SDK probes and other Apple modes are untouched. The parent's exact command
    admission arms this child only around its one generator/verifier command.
    No user callback, STOP poll, filesystem or native operation runs here.
    """
    from .desktop_apple_provisioning import AppleProvisioningRun
    _need(type(operation) is AppleProvisioningRun)
    if operation.request.context["mode"] not in MODES:
        return
    child = getattr(operation, "_distribution_key", None)
    if child is None:
        return
    _need(type(child) is AppleDistributionKeyWork and child._operation is operation)
    if child._command_active:
        child.bind_command_slot(engine, slot)


class AppleDistributionKeyWork:
    """One finite borrower; the Apple parent owns ACKs and final handoff.

    The parent private output child may borrow the retained _frame ONLY after
    checking this SAME child/original slot; there is intentionally no generic
    bytes callback/getter. A generated/possible key cannot be retired by this
    module. Parent v3 must implement the separate durable keySaved handoff and
    native disposal before enabling local preparation.
    """
    __slots__ = ("_operation", "_source", "_runtime", "_mode", "_material", "_started", "_claimed",
                 "_complete", "_retired", "_scratch", "_input", "_private_input", "_slot", "_result",
                 "_frame", "_parts", "_failure", "_command_active", "_pending_ack")

    def __init__(self, operation):
        from .desktop_apple_provisioning import AppleProvisioningRun
        _need(type(operation) is AppleProvisioningRun and operation.source.require_operation() is operation
              and operation.request.context["mode"] in MODES and operation.runtime is not None
              and operation.invocation is not None and getattr(operation, "_distribution_key", None) is None)
        operation.checkpoint()
        self._operation, self._source, self._runtime = operation, operation.source, operation.runtime
        self._mode = operation.request.context["mode"]
        self._material = self._scratch = self._input = self._private_input = self._slot = self._result = None
        self._frame = self._parts = self._failure = self._pending_ack = None
        self._started = self._claimed = self._complete = self._retired = self._command_active = False
        operation._distribution_key = self  # BEFORE any private read/command/scratch.
        if self._mode != PREPARE_MODE:
            # The original input owns this single tuple and all partial reads.
            # Parent's fixed accessor is not an ordinary Store/Signing loan.
            self._material = self._source.distribution_key_material(operation)
            _need(type(self._material) is tuple and len(self._material) == 3)

    def __repr__(self):
        return "<AppleDistributionKeyWork private>"

    def _binding(self, operation):
        _need(operation is self._operation and operation.source is self._source and operation.runtime is self._runtime
              and operation._distribution_key is self and not self._retired
              and self._source.require_operation() is operation and operation.request.context["mode"] == self._mode)
        operation.checkpoint()
        self._runtime.require(root=operation.root, invocation=operation.invocation)
        if self._mode != PREPARE_MODE:
            _need(self._source.distribution_key_material(operation) is self._material)

    def bind_scratch(self, scratch):
        # SAME FiniteScratch constructor binds before native acquisition.
        _need(type(scratch) is FiniteScratch and self._scratch is None)
        self._scratch = scratch
        self._binding(self._operation)
        _need(self._started and not self._claimed and scratch.layout == ("online-runner" if self._mode == PREPARE_MODE else LAYOUT)
              and scratch.cancellation is self._operation.guard and scratch.journal is None and scratch._lane_binding is None
              and not scratch.active and not scratch.claimed and not scratch.created
              and scratch.slot.number is None and not scratch.parent.slots)

    def argv(self, runtime):
        self._binding(self._operation)
        _need(runtime is self._runtime and type(self._scratch) is FiniteScratch)
        name = "apple_distribution_key.rb" if self._mode == PREPARE_MODE else "apple_distribution_key_verify.rb"
        if self._mode in {"certificate-review", "certificate-create", "certificate-reconcile"}:
            # Same actual key verifier, preceded by fixed offline resources.
            # A missing/invalid G3/root refuses BEFORE any certificate POST.
            name = "apple_distribution_certificate_prepare.rb"
        argv = ("bundle", "exec", "ruby", str(runtime.tooling_root / "fastlane" / name))
        if self._mode != PREPARE_MODE:
            _need(self._input is not None)
            argv += (str(self._scratch.require(self._input)),)
        return argv

    def admit_command(self, runtime, argv, *, environ):
        """Fixed call from SAME parent's command_arguments before run_owned."""
        self._binding(self._operation)
        _need(self._started and not self._claimed and not self._complete and self._failure is None
              and tuple(argv) == self.argv(runtime) and type(environ) is dict and environ == self._operation._base_environment())
        if self._mode == PREPARE_MODE:
            # Receiving a digest is not native permission. The actual parent
            # must already have durably saved its one pre-generation intent;
            # this fixed input method consumes only that original ACK handoff.
            self._pending_ack = self._source.consume_key_pending_ack(self._operation, self)
            _need(type(self._pending_ack) is str and len(self._pending_ack) == 64
                  and all(byte in "0123456789abcdef" for byte in self._pending_ack))
        self._claimed = True
        self._command_active = True

    def bind_command_slot(self, engine, slot):
        """Memory-only hook BEFORE C/A/W acquisition; no STOP/FS/native IO."""
        from ._command_process import CommandOutcomeSlot, _Outer
        _need(self._started and self._claimed and self._slot is None and not self._retired
              and self._operation._distribution_key is self and self._operation.source is self._source
              and self._operation.runtime is self._runtime and self._operation.request.context["mode"] == self._mode
              and type(slot) is CommandOutcomeSlot and type(engine) is _Outer and slot._engine is engine
              and engine.slot is slot and engine.guard is self._operation.guard and engine.scope is None
              and engine.binding is None and engine.owns is False and engine.evidence is None
              and engine._store_timing is None and engine.text is False)
        self._slot = slot  # Retains raw output even if the ordinary ledger folds a known close.

    def _outcome(self):
        # Reuse the actual fixed original-slot inspector, not a count/status or
        # a result-shaped finality receipt. No new command owner is created.
        from ._desktop_ios_signed_operation import original_outcome
        return original_outcome(self._slot, self._operation.guard, None, None)

    def _capture_returned(self):
        outcome = self._outcome()
        if outcome is None:
            return False  # Unknown producer/readers retain the exact slot, no parsing/adoption.
        engine = self._slot._engine
        if outcome.no_target is not None:
            _need(not any(engine.outputs) and self._frame is None)
            return False
        # The original result can be fully formed even when a later STOP
        # raises rather than returns CompletedProcess. Capture it FIRST, then
        # check its shape; failed/partial material stays rooted in the slot.
        if outcome.result_integrity != "complete" or engine.decoded is None:
            return False
        raw, error = engine.decoded
        self._frame = raw
        _need(type(raw) is bytes and type(error) is bytes and error == b"" and outcome.returncode == 0)
        self._parts = _parts(raw, public=self._mode != PREPARE_MODE)
        if self._mode != PREPARE_MODE:
            expected = _parts(self._private_input, public=False)
            _need(self._parts[0] == expected[1] and self._parts[1] == expected[2])
        return True

    def run(self):
        self._binding(self._operation)
        _need(not self._started)
        self._started = True
        try:
            layout = "online-runner" if self._mode == PREPARE_MODE else LAYOUT
            with finite_scratch(layout=layout, cancellation=self._operation.guard,
                                parent=self._runtime.private_directory) as scratch:
                _need(self._scratch is scratch)
                if self._mode != PREPARE_MODE:
                    self._private_input = _stored_frame(self._material)
                    self._input = scratch.put("pending-key", self._private_input)
                argv = self.argv(self._runtime)
                with self._runtime.command(argv, capture=True):
                    try:
                        # Base runtime environment only. No P8, PKCS8, CSR,
                        # password or project label is in argv/environment.
                        self._result = run_owned(argv, environ=self._operation._base_environment(),
                            cwd=scratch._path, timeout=60, capture=True, text=False,
                            output_limit=PRIVATE_LIMIT if self._mode == PREPARE_MODE else PUBLIC_LIMIT,
                            cancellation=self._operation.guard)
                    except BaseException as error:
                        # Preserve the original first failure BEFORE a
                        # fallible output/decode/retention postcheck.
                        self._failure = True
                        self._operation.remember(error)
                        raise
                    finally:
                        original_error = sys.exc_info()[1]
                        try:
                            self._capture_returned()  # Preserve output on raised return too.
                        except BaseException as error:
                            self._failure = True
                            self._operation.remember(error)
                            if original_error is None:
                                raise
                        finally:
                            self._command_active = False
                    _need(self._claimed and self._result.returncode == 0 and self._result.stderr == b""
                          and self._frame is not None and self._result.stdout == self._frame and self._parts is not None)
                    if self._input is not None:
                        scratch.require(self._input)
                    self._binding(self._operation)
            self._complete = True
            return self
        except BaseException as error:
            self._failure = True  # Error/traceback is retained by the original operation only.
            self._operation.remember(error)
            raise

    def _scratch_closed(self):
        scratch = self._scratch
        return (scratch is not None and scratch.claimed and not scratch.active and scratch._cleanup_complete
                and not scratch.created and all(slot.number is None and slot.close_state == "CLOSED"
                    for slot in (*scratch.writer_slots, scratch.slot, *scratch.parent.slots)))

    def verified_public_parts(self, operation):
        """Public DATA for the fresh-key-loan parent; never local-prep export."""
        self._binding(operation)
        _need(self._mode in VERIFY_MODES and self._complete and self._failure is None
              and self._parts is not None and self._scratch_closed() and self._outcome() is not None)
        # Only the actual bundled Ruby verifier examined PKCS8/CSR/SPKI and
        # signed a fixed local challenge. Native current-key/ACK/account/chain
        # authority still belongs to the enclosing original operation.
        return bytes(self._parts[0]), bytes(self._parts[1])

    def _never_generated(self):
        if not self._claimed and self._slot is None and self._frame is None and self._parts is None:
            return self._mode == PREPARE_MODE  # The fixed command admission never entered.
        outcome = self._outcome()
        # A failed generator with empty output is NOT no-generation evidence.
        return (self._mode == PREPARE_MODE and outcome is not None and outcome.no_target is not None
                and self._frame is None and self._parts is None and not any(self._slot._engine.outputs))

    def retire_non_generated(self, operation):
        """Only a verifier loan or actual no-target preparation can use this.

        A generated key requires the future fixed parent keySaved ACK/private
        handoff path. This child deliberately has NO generated-key discard or
        generic 'delivered' method. No-save/ordinary process close is not it.
        """
        _need(operation is self._operation and operation._distribution_key is self and operation.source is self._source
              and operation._close_claimed and operation._pending is None)
        if self._retired:
            return
        verdict = operation.guard.lifetime_ledger.verdict()
        _need(verdict.complete and not verdict.fatal and (self._scratch_closed() or self._scratch is None and not self._claimed))
        if self._mode == PREPARE_MODE:
            _need(self._never_generated())
        elif self._slot is not None:
            _need(self._outcome() is not None)
        self._material = self._private_input = self._result = self._frame = self._parts = self._slot = None
        self._retired = True

    def private_closed(self):
        return (self._retired and self._material is None and self._private_input is None and self._result is None
                and self._frame is None and self._parts is None and self._slot is None)
