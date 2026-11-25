"""One fixed PKCS12 packaging command inside the ORIGINAL Apple operation.

No issuer/key generation, independent runner, caller algorithm/path, trust
constructor or public private-material getter. Fresh network-read certificate
verification and durable LOCAL-save Pending are separate parent prerequisites.
The native parent retains the raw output before any ACK; a JSON result cannot
authorize the later NEW save or substitute for original joins.
"""
from __future__ import annotations

import hashlib
import struct
import sys

from .apple_provisioning_api import ProvisioningError
from .build_inputs import FiniteScratch, finite_scratch
from .owned_process import run_owned
from ._desktop_apple_distribution_key import _stored_frame

MODE = "p12-save"
LAYOUT = "apple-p12-assembly"
MAGIC = b"MRK-APPLE-P12/1\n"
CERTIFICATES_MAGIC = b"MRK-APPLE-P12-CERTIFICATES/1\n"
P12_LIMIT = 1024 * 1024
CERTIFICATE_LIMIT = 64 * 1024
CERTIFICATES_LIMIT = 128 * 1024
HEADER = len(MAGIC) + 4 + 64
PRIVATE_LIMIT = HEADER + P12_LIMIT
PASSWORD_BYTES = 64


def _need(condition):
    if not condition:
        raise ProvisioningError("apple_p12_packaging_refused")


def _parts(raw):
    """Borrowing framing DATA only, not certificate/PKCS12 validation."""
    _need(type(raw) is bytes and HEADER < len(raw) <= PRIVATE_LIMIT and raw.startswith(MAGIC))
    length = struct.unpack_from(">I", raw, len(MAGIC))[0]
    _need(0 < length <= P12_LIMIT and HEADER + length == len(raw))
    hashes = len(MAGIC) + 4
    return (memoryview(raw)[HEADER:], memoryview(raw)[hashes:hashes + 32], memoryview(raw)[hashes + 32:HEADER])


def output_metadata(raw):
    p12, leaf, spki = _parts(raw)
    return {"frameBytes": len(raw), "frameSha256": hashlib.sha256(raw).hexdigest(),
            "p12Bytes": len(p12), "p12Sha256": hashlib.sha256(p12).hexdigest(),
            "leafSha256": leaf.hex(), "spkiSha256": spki.hex()}


def _certificates_frame(leaf, intermediate, root):
    # This fixed serialization takes PUBLIC DER already retained by the same
    # fresh certificate phase. The frame is never proof that those bytes are
    # Apple/distribution/current or associated with a held private key.
    values = (leaf, intermediate, root)
    _need(all(type(value) is bytes and 0 < len(value) <= CERTIFICATE_LIMIT for value in values)
          and sum(map(len, values)) <= CERTIFICATES_LIMIT and len(set(values)) == 3)
    return CERTIFICATES_MAGIC + struct.pack(">III", *map(len, values)) + b"".join(values)


def bind_original_command_slot(operation, engine, slot):
    """One fixed _Outer constructor hook BEFORE its original acquisition."""
    from .desktop_apple_provisioning import AppleProvisioningRun
    _need(type(operation) is AppleProvisioningRun)
    if operation.request.context["mode"] != MODE:
        return
    child = operation._p12_assembly
    if child is not None and child._command_active:
        _need(type(child) is P12AssemblyWork and child._operation is operation)
        child.bind_command_slot(engine, slot)


class P12AssemblyWork:
    __slots__ = ("_operation", "_source", "_runtime", "_steps", "_material", "_certificates", "_leaf_hash",
                 "_spki_hash", "_pending_ack", "_started", "_claimed", "_complete", "_retired", "_scratch",
                 "_inputs", "_private_input", "_slot", "_result", "_frame", "_parts", "_failure", "_command_active")

    def __init__(self, operation):
        from .desktop_apple_provisioning import AppleProvisioningRun
        from ._desktop_apple_p12_worker import P12Steps
        _need(type(operation) is AppleProvisioningRun and operation.source.require_operation() is operation
              and operation.request.context["mode"] == MODE and operation.runtime is not None
              and operation.invocation is not None and operation._p12_assembly is None
              and type(operation._p12_steps) is P12Steps)
        operation.checkpoint()
        self._operation, self._source, self._runtime, self._steps = operation, operation.source, operation.runtime, operation._p12_steps
        self._material = self._certificates = self._leaf_hash = self._spki_hash = self._pending_ack = None
        self._scratch = self._private_input = self._slot = self._result = self._frame = self._parts = self._failure = None
        self._inputs = ()
        self._started = self._claimed = self._complete = self._retired = self._command_active = False
        operation._p12_assembly = self # Retained BEFORE private input/scratch/command.
        self._material = self._source.p12_material(operation)
        _need(type(self._material) is tuple and len(self._material) == 4
              and all(type(part) is bytes for part in self._material)
              and len(self._material[3]) == PASSWORD_BYTES
              and all(byte in b"0123456789abcdef" for byte in self._material[3]))
        self._certificates, self._leaf_hash, self._spki_hash = self._steps.assembly_inputs(operation)
        _need(type(self._certificates) is bytes and 0 < len(self._certificates) <= CERTIFICATE_LIMIT
              and hashlib.sha256(self._certificates).hexdigest() == self._leaf_hash
              and type(self._leaf_hash) is str and type(self._spki_hash) is str
              and all(len(value) == 64 and all(byte in "0123456789abcdef" for byte in value)
                      for value in (self._leaf_hash, self._spki_hash)))

    def __repr__(self):
        return "<P12AssemblyWork private>"

    def _binding(self, operation):
        _need(operation is self._operation and operation.source is self._source and operation.runtime is self._runtime
              and operation._p12_assembly is self and operation._p12_steps is self._steps and not self._retired
              and self._source.require_operation() is operation and operation.request.context["mode"] == MODE
              and self._source.p12_material(operation) is self._material)
        operation.checkpoint()
        self._runtime.require(root=operation.root, invocation=operation.invocation)
        _need(self._steps.assembly_inputs(operation)[0] is self._certificates)

    def bind_scratch(self, scratch):
        _need(type(scratch) is FiniteScratch and self._scratch is None)
        self._scratch = scratch # Even an acquire refusal remains original-owned.
        self._binding(self._operation)
        _need(self._started and not self._claimed and scratch.layout == LAYOUT
              and scratch.cancellation is self._operation.guard and scratch.journal is None and scratch._lane_binding is None
              and not scratch.active and not scratch.claimed and not scratch.created
              and scratch.slot.number is None and not scratch.parent.slots)

    def argv(self, runtime):
        self._binding(self._operation)
        _need(runtime is self._runtime and type(self._scratch) is FiniteScratch and len(self._inputs) == 3)
        return ("bundle", "exec", "ruby", str(runtime.tooling_root / "fastlane/apple_provisioning_p12_assemble.rb"),
                *(str(self._scratch.require(original)) for original in self._inputs))

    def admit_command(self, runtime, argv, *, environ):
        self._binding(self._operation)
        _need(self._started and not self._claimed and not self._complete and self._failure is None
              and tuple(argv) == self.argv(runtime) and type(environ) is dict and environ == self._operation._base_environment())
        # This original native CAS is tagged LOCAL P12 save, not provider-send
        # or key-generation authority. Lost/ambiguous ACK is never retried.
        self._pending_ack = self._source.consume_p12_pending_ack(self._operation, self)
        _need(type(self._pending_ack) is str and len(self._pending_ack) == 64
              and all(byte in "0123456789abcdef" for byte in self._pending_ack))
        self._claimed = self._command_active = True

    def bind_command_slot(self, engine, slot):
        from ._command_process import CommandOutcomeSlot, _Outer
        _need(self._started and self._claimed and self._slot is None and not self._retired
              and self._operation._p12_assembly is self and self._operation.source is self._source
              and self._operation.runtime is self._runtime and self._operation.request.context["mode"] == MODE
              and type(slot) is CommandOutcomeSlot and type(engine) is _Outer and slot._engine is engine
              and engine.slot is slot and engine.guard is self._operation.guard and engine.scope is None
              and engine.binding is None and engine.owns is False and engine.evidence is None
              and engine._store_timing is None and engine.text is False)
        self._slot = slot

    def _outcome(self):
        from ._desktop_ios_signed_operation import original_outcome
        return original_outcome(self._slot, self._operation.guard, None, None)

    def _capture_returned(self):
        outcome = self._outcome()
        if outcome is None or outcome.no_target is not None or outcome.result_integrity != "complete":
            return False
        engine = self._slot._engine
        if engine.decoded is None:
            return False
        raw, error = engine.decoded
        self._frame = raw # Retain before type/status/parsing/postcheck, including failed output.
        _need(type(raw) is bytes and type(error) is bytes and error == b"" and outcome.returncode == 0)
        self._parts = _parts(raw)
        _need(self._parts[1].hex() == self._leaf_hash and self._parts[2].hex() == self._spki_hash)
        return True

    def run(self):
        self._binding(self._operation)
        _need(not self._started)
        self._started = True
        try:
            with finite_scratch(layout=LAYOUT, cancellation=self._operation.guard, parent=self._runtime.private_directory) as scratch:
                _need(self._scratch is scratch)
                self._private_input = _stored_frame(self._material[:3])
                # Each returned file object is retained immediately, so a
                # later put/refusal cannot erase an already created original.
                for role, value in (("pending-key", self._private_input), ("p12-password", self._material[3]),
                                    ("certificate", self._certificates)):
                    self._inputs += (scratch.put(role, value),)
                argv = self.argv(self._runtime)
                with self._runtime.command(argv, capture=True):
                    try:
                        self._result = run_owned(argv, environ=self._operation._base_environment(), cwd=scratch._path,
                            timeout=60, capture=True, text=False, output_limit=PRIVATE_LIMIT, cancellation=self._operation.guard)
                    except BaseException as error:
                        self._failure = True
                        self._operation.remember(error)
                        raise
                    finally:
                        original_error = sys.exc_info()[1]
                        try:
                            self._capture_returned()
                        except BaseException as error:
                            self._failure = True
                            self._operation.remember(error)
                            if original_error is None:
                                raise
                        finally:
                            self._command_active = False
                    _need(self._claimed and self._result.returncode == 0 and self._result.stderr == b""
                          and self._frame is not None and self._result.stdout == self._frame and self._parts is not None)
                    for original in self._inputs:
                        scratch.require(original)
                    self._binding(self._operation)
            self._complete = True
            return self
        except BaseException as error:
            self._failure = True
            self._operation.remember(error)
            raise

    def _scratch_closed(self):
        scratch = self._scratch
        return (type(scratch) is FiniteScratch and scratch.claimed and not scratch.active and scratch._cleanup_complete
                and not scratch.created and all(slot.number is None and slot.close_state == "CLOSED"
                    for slot in (*scratch.writer_slots, scratch.slot, *scratch.parent.slots)))

    def _never_assembled(self):
        if self._frame is not None or self._parts is not None or self._result is not None:
            return False
        if not self._claimed and self._slot is None:
            return True # Only comparison DATA; native all-jobs proof is separate.
        outcome = self._outcome()
        return (outcome is not None and outcome.no_target is not None and self._slot is not None
                and not any(self._slot._engine.outputs))

    def private_closed(self):
        return (self._retired and not self._command_active and self._material is None and self._private_input is None
                and self._slot is None and self._frame is None and self._parts is None and self._result is None)

    def retire(self, output):
        """Release Python references only after the original worker cut.

        The native original receive/password remains retained until its own
        SavePermit or exact known-never-save proof. No STOP/empty result by
        itself qualifies either side's private disposal.
        """
        from ._desktop_apple_p12_private import P12Output
        op = self._operation
        _need(type(output) is P12Output and op._p12_output is output and output._child is self
              and op._close_claimed and op._pending is None and not self._retired and not self._command_active)
        verdict = op.guard.lifetime_ledger.verdict()
        _need(verdict.cleanup_complete and verdict.contained and verdict.profile_calls == 0
              and not verdict.fatal and (self._scratch is None or self._scratch_closed()))
        if self._frame is not None:
            returned = self._outcome()
            _need(output._raw is self._frame and returned is not None and returned.no_target is None
                  and returned.result_integrity == "complete" and returned.returncode == 0
                  and self._parts is not None and self._slot._engine.decoded[1] == b"")
            _need((output._body_done and output._acknowledged) or
                  (not output._claimed and output._bytes == 0 and output._ack is None
                   and isinstance(op.primary, KeyboardInterrupt)))
        else:
            _need(self._never_assembled())
        self._material = self._private_input = self._slot = self._result = self._frame = self._parts = None
        self._inputs = ()
        self._retired = True
