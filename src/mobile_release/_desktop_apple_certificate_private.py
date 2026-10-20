"""Six fixed input roles and one public leaf check in the existing owner.

The stored key's private fields never enter JSON/control/output. The existing
native Loan retains their originals; this receiver keeps each partial part
before another read. No generated key, new receiver FD, runner or clock lives
here. A public offline proof still needs original native/capture finality.
"""
from __future__ import annotations

import json
import struct

from . import _desktop_apple_certificate_protocol as wire
from . import apple_provisioning_api as api
from ._desktop_preflight_protocol import _pairs
from ._desktop_store_preflight_control import PREFIX, SUFFIX, HEADER_LIMIT
from .build_inputs import FiniteScratch, finite_scratch
from .owned_process import run_owned

ROLES = (("asc-p8", 16 * 1024), ("asc-key-id", 10), ("asc-issuer-id", 36),
         ("apple-key-pkcs8-base64", 4096), ("apple-key-csr", 4096), ("apple-key-spki-base64", 1368))
MAGIC = b"MRK-APPLE-DISTRIBUTION-CERTIFICATE/1\n"
INPUT_LIMIT = len(MAGIC) + 4 * 64 + 10 + 4 + 64 * 1024
OUTPUT_LIMIT = 2048


def material_header(raw):
    wire.need(type(raw) is bytes and 0 < len(raw) <= HEADER_LIMIT and raw.endswith(b"\n"))
    value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: wire.need(False))
    wire.need(type(value) is dict and set(value) == {"schemaVersion", "files"}
              and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
              and type(value["files"]) is list and len(value["files"]) == len(ROLES))
    lengths = []
    for row, (role, limit) in zip(value["files"], ROLES):
        wire.need(type(row) is dict and set(row) == {"role", "bytes"} and row["role"] == role
                  and type(row["bytes"]) is int and 1 <= row["bytes"] <= limit
                  and (role not in {"asc-key-id", "asc-issuer-id"} or row["bytes"] == limit))
        lengths.append(row["bytes"])
    return tuple(lengths)


def receive_material(source, operation, scratch):
    from .desktop_apple_provisioning import AppleProvisioningRun
    from ._desktop_apple_provisioning_control import AppleProvisioningInput
    wire.need(type(source) is AppleProvisioningInput and type(operation) is AppleProvisioningRun
        and operation.source is source and source.require_operation() is operation
        and operation.request.context["mode"] in wire.MODES and operation.invocation is not None
        and operation.runtime is not None and type(scratch) is FiniteScratch and scratch in operation.scratches
        and scratch.layout == "store-selection" and scratch.cancellation is operation.guard
        and not source._material_read and source.material_pending and not source.material_receiving and not source.reading
        and source._certificate_material is None and source._certificate_parts is None and source._certificate_key_parts is None)
    operation.checkpoint()
    source._material_read = source.material_receiving = True
    source._certificate_parts = []
    try:
        wire.need(source._take(len(PREFIX), audit=False) == PREFIX)
        raw = bytearray()
        while not raw.endswith(b"\n"):
            wire.need(len(raw) < HEADER_LIMIT)
            raw.extend(source._take(1, audit=False))
        for length in material_header(bytes(raw)):
            source._certificate_parts.append(bytes(source._take(length, audit=False)))
        wire.need(source._take(len(SUFFIX), audit=False) == SUFFIX)
        source._certificate_material = tuple(source._certificate_parts)
        source._certificate_parts = None
        source._material = source._certificate_material[:3]
        source._certificate_key_parts = source._certificate_material[3:]
        operation.validate_apple_shape(source._material)
        wire.need(all(part.isascii() and b"\0" not in part for part in source._certificate_key_parts))
        snapshot = scratch.put("asc-p8", source._material[0])
        source.material_pending = False
    except BaseException as error:
        operation.remember(error)
        raise
    finally:
        source.material_receiving = False
        source.read_remaining = 0
    operation.checkpoint()
    return snapshot


def distribution_key_material(source, operation):
    from .desktop_apple_provisioning import AppleProvisioningRun
    from ._desktop_apple_provisioning_control import AppleProvisioningInput
    wire.need(type(source) is AppleProvisioningInput and type(operation) is AppleProvisioningRun
        and operation.source is source and source.require_operation() is operation
        and operation.request.context["mode"] in wire.MODES and source._material_read and not source.close_claimed
        and not source.material_receiving and not source.material_pending
        and type(source._certificate_material) is tuple and len(source._certificate_material) == 6
        and type(source._material) is tuple and len(source._material) == 3
        and type(source._certificate_key_parts) is tuple and len(source._certificate_key_parts) == 3
        and all(left is right for left, right in zip(source._material, source._certificate_material[:3]))
        and all(left is right for left, right in zip(source._certificate_key_parts, source._certificate_material[3:])))
    operation.checkpoint()
    return source._certificate_key_parts


class CertificatePolicyWork:
    """One closed public-leaf command, never arbitrary trust input options."""
    def __init__(self, operation, leaf, identity_ack):
        from .desktop_apple_provisioning import AppleProvisioningRun
        wire.need(type(operation) is AppleProvisioningRun and operation.source.require_operation() is operation
                  and operation._certificate is not None and operation._certificate.policy is None
                  and type(leaf) is bytes and 0 < len(leaf) <= wire.CERTIFICATE_BYTES and wire.common.sha(identity_ack))
        self.operation = operation
        self.scratch = self.input = self.result = None
        self.claimed = False
        self.leaf = leaf
        self.identity_ack = identity_ack
        self.body = (MAGIC + operation.request.digest.encode("ascii") + identity_ack.encode("ascii") +
            api.digest(leaf).encode("ascii") + operation._certificate.public_csr.public_key_sha256.encode("ascii") +
            operation.target.team_id.encode("ascii") + struct.pack(">I", len(leaf)) + leaf)
        wire.need(len(self.body) <= INPUT_LIMIT)
        operation._certificate.policy = self  # Before scratch/command admission.

    def bind_scratch(self, scratch):
        op = self.operation
        wire.need(type(scratch) is FiniteScratch and scratch.layout == "apple-distribution-certificate"
                  and scratch.cancellation is op.guard and self.scratch is None and op._certificate.policy is self
                  and not scratch.active and not scratch.claimed and scratch.slot.number is None)
        self.scratch = scratch

    def argv(self):
        op = self.operation
        wire.need(op._certificate.policy is self and self.scratch is not None and self.input is not None)
        return ("bundle", "exec", "ruby", str(op.runtime.tooling_root / "fastlane/apple_distribution_certificate_verify.rb"),
                str(self.scratch.require(self.input)))

    def admit(self, argv, environ):
        op = self.operation
        wire.need(op._certificate.policy is self and not self.claimed and tuple(argv) == self.argv()
                  and environ == op._base_environment() and op._wire_request is None)
        op.check(op.context)
        self.claimed = True

    def run(self):
        op = self.operation
        op._certificate.current_key()
        with finite_scratch(layout="apple-distribution-certificate", cancellation=op.guard,
                            parent=op.runtime.private_directory) as scratch:
            wire.need(scratch is self.scratch)
            self.input = scratch.put("certificate", self.body)
            previous = op.guard.lifetime_ledger.verdict().commands
            with op.runtime.command(self.argv(), capture=True):
                result = run_owned(self.argv(), cwd=scratch._path, environ=op._base_environment(),
                    capture=True, text=False, timeout=60, output_limit=OUTPUT_LIMIT, cancellation=op.guard)
            self.result = result  # Keep the actual return before further checks.
            verdict = op.guard.lifetime_ledger.verdict()
            wire.need(self.claimed and verdict.cleanup_complete and verdict.contained and verdict.command_dispatched is not None
                      and verdict.commands == previous + 1 and verdict.profile_calls == 0
                      and result.returncode == 0 and type(result.stdout) is bytes and result.stderr == b""
                      and 0 < len(result.stdout) <= OUTPUT_LIMIT)
            value = wire.validate_policy(api.document(result.stdout))
            wire.need(value["requestBindingSha256"] == op.request.digest and value["certificateSha256"] == api.digest(self.leaf)
                      and value["identityAckSha256"] == self.identity_ack
                      and value["teamId"] == op.target.team_id and value["publicKeySha256"] == op._certificate.public_csr.public_key_sha256)
            scratch.require(self.input)
        op._certificate.current_key()
        return value
