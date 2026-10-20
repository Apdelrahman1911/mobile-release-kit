"""Fixed private input/output on the SAME Apple process pipe originals.

Key/P8 parts are borrowed from the retained native source; the generated
password has one fixed role only for p12-save. Optional selected P12 parts use
the existing BoundLoan/extraction route. No private body enters JSON or a
result. All partials remain rooted until genuine original close/join cuts.
"""
import hashlib
import json
import os
import select
import struct

from . import _desktop_apple_p12_protocol as wire
from . import apple_provisioning_api as api
from ._desktop_preflight_protocol import _pairs
from ._desktop_store_preflight_control import PREFIX, SUFFIX, HEADER_LIMIT
from ._desktop_apple_p12_assembly import P12AssemblyWork, PRIVATE_LIMIT, output_metadata, _parts
from .build_inputs import FiniteScratch

BASE_ROLES = (("asc-p8", 16 * 1024), ("asc-key-id", 10), ("asc-issuer-id", 36),
              ("apple-key-pkcs8-base64", 4096), ("apple-key-csr", 4096), ("apple-key-spki-base64", 1368))
MAGIC = b"MRK-APPLE-P12-TRANSFER/1\n"
HEADER = struct.Struct(">I32s32s")
TRANSFER_LIMIT = len(MAGIC) + HEADER.size + PRIVATE_LIMIT


def material_header(raw, request):
    wire.need(type(raw) is bytes and 0 < len(raw) <= HEADER_LIMIT and raw.endswith(b"\n"))
    mode, selected = request.context["mode"], request.native["p12"]["selectedP12"]
    wire.need(mode in wire.MODES and not (mode == "p12-save" and selected is not None))
    roles = BASE_ROLES + ((("p12-password", 64),) if mode == "p12-save" else
                         (("distribution-p12", 4 * 1024 * 1024), ("p12-password", 4096)) if selected is not None else ())
    value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: wire.need(False))
    wire.need(type(value) is dict and set(value) == {"schemaVersion", "files"}
              and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
              and type(value["files"]) is list and len(value["files"]) == len(roles))
    lengths = []
    for row, (role, limit) in zip(value["files"], roles):
        wire.need(type(row) is dict and set(row) == {"role", "bytes"} and row["role"] == role
                  and type(row["bytes"]) is int and 1 <= row["bytes"] <= limit
                  and (role not in {"asc-key-id", "asc-issuer-id"} or row["bytes"] == limit)
                  and (mode != "p12-save" or role != "p12-password" or row["bytes"] == 64))
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
              and source._p12_material is None and source._p12_parts is None and source._certificate_material is None)
    operation.checkpoint()
    source._material_read = source.material_receiving = True
    source._p12_parts = []  # Retained BEFORE even a header/partial part can fail.
    try:
        wire.need(source._take(len(PREFIX), audit=False) == PREFIX)
        raw = bytearray()
        while not raw.endswith(b"\n"):
            wire.need(len(raw) < HEADER_LIMIT)
            raw.extend(source._take(1, audit=False))
        for length in material_header(bytes(raw), operation.request):
            source._p12_parts.append(bytes(source._take(length, audit=False)))
        wire.need(source._take(len(SUFFIX), audit=False) == SUFFIX)
        source._p12_material = tuple(source._p12_parts)
        source._p12_parts = None
        source._certificate_material = source._p12_material[:6]
        source._material = source._certificate_material[:3]
        source._certificate_key_parts = source._certificate_material[3:]
        operation.validate_apple_shape(source._material)
        wire.need(all(part.isascii() and b"\0" not in part for part in source._certificate_key_parts))
        if operation.request.context["mode"] == "p12-save":
            password = source._p12_material[6]
            wire.need(len(password) == 64 and all(byte in b"0123456789abcdef" for byte in password))
            source._p12_assembly_material = source._certificate_key_parts + (password,)
        elif operation.request.native["p12"]["selectedP12"] is not None:
            from ._desktop_apple_provisioning_p12 import _material
            source._profile_material = _material(source._material + source._p12_material[6:])
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


def _material_binding(source, operation):
    from .desktop_apple_provisioning import AppleProvisioningRun
    from ._desktop_apple_provisioning_control import AppleProvisioningInput
    wire.need(type(source) is AppleProvisioningInput and type(operation) is AppleProvisioningRun
              and operation.source is source and source.require_operation() is operation
              and operation.request.context["mode"] in wire.MODES and source._material_read and not source.close_claimed
              and not source.material_pending and not source.material_receiving and type(source._p12_material) is tuple
              and type(source._certificate_material) is tuple and len(source._certificate_material) == 6
              and type(source._material) is tuple and len(source._material) == 3
              and type(source._certificate_key_parts) is tuple and len(source._certificate_key_parts) == 3
              and all(a is b for a, b in zip(source._certificate_material, source._p12_material[:6]))
              and all(a is b for a, b in zip(source._material, source._certificate_material[:3]))
              and all(a is b for a, b in zip(source._certificate_key_parts, source._certificate_material[3:])))
    operation.checkpoint()


def distribution_key_material(source, operation):
    _material_binding(source, operation)
    return source._certificate_key_parts


def p12_material(source, operation):
    _material_binding(source, operation)
    value = source._p12_assembly_material
    wire.need(operation.request.context["mode"] == "p12-save" and len(source._p12_material) == 7
              and type(value) is tuple and len(value) == 4
              and all(a is b for a, b in zip(value[:3], source._certificate_key_parts))
              and value[3] is source._p12_material[6])
    return value


def profile_material(source, operation):
    _material_binding(source, operation)
    value = source._profile_material
    wire.need(operation.request.context["mode"] in {"p12-review", "p12-reuse"}
              and operation.request.native["p12"]["selectedP12"] is not None
              and len(source._p12_material) == 8 and type(value) is tuple and len(value) == 5
              and all(a is b for a, b in zip(value[:3], source._material))
              and all(a is b for a, b in zip(value[3:], source._p12_material[6:])))
    return value


def header(request_sha256, raw):
    wire.need(wire.common.sha(request_sha256))
    _parts(raw)
    return MAGIC + HEADER.pack(len(raw), bytes.fromhex(request_sha256), hashlib.sha256(raw).digest())


class P12Output:
    def __init__(self, operation):
        from .desktop_apple_provisioning import AppleProvisioningRun
        from ._desktop_apple_provisioning_engine import _Engine
        wire.need(type(operation) is AppleProvisioningRun and operation.source.require_operation() is operation
                  and operation.request.context["mode"] == "p12-save" and type(operation.source.engine) is _Engine
                  and operation._p12_output is None and operation._p12_assembly is None)
        self._operation, self._engine, self._request = operation, operation.source.engine, operation.request
        self._child = self._raw = self._metadata = self._header = self._ack = None
        self._claimed = self._body_done = self._acknowledged = self._worker_retired = self._closed = False
        self._bytes = 0
        operation._p12_output = self

    def __repr__(self):
        return "<P12Output private>"

    def _binding(self):
        op = self._operation
        wire.need(op._p12_output is self and op.source.require_operation() is op and op.source.engine is self._engine
                  and op.request is self._request and op.request.context["mode"] == "p12-save" and not self._closed)
        return op

    def retain_returned(self, child):
        op = self._binding()
        wire.need(type(child) is P12AssemblyWork and child is op._p12_assembly and child._operation is op
                  and child._source is op.source and child._runtime is op.runtime
                  and not child._retired and not child._command_active and self._child is None and not self._claimed)
        self._child = child
        self._raw = child._frame  # Keep any returned private bytes before validation can fail.
        returned = child._outcome()
        wire.need(returned is not None and returned.no_target is None and returned.result_integrity == "complete"
                  and returned.returncode == 0 and child._scratch_closed() and child._parts is not None
                  and child._slot._engine.decoded[0] is self._raw and child._slot._engine.decoded[1] == b"")
        value = output_metadata(self._raw)
        self._metadata = {**{key: value[key] for key in ("frameBytes", "frameSha256", "p12Bytes", "p12Sha256")},
                          "certificateSha256": value["leafSha256"], "publicKeySha256": value["spkiSha256"]}
        wire.output_metadata(self._metadata)
        self._header = header(self._request.digest, self._raw)

    def metadata(self):
        self._binding()
        wire.need(self._metadata is not None and self._raw is not None and not self._claimed)
        return dict(self._metadata)

    def begin_transfer(self):
        self._binding()
        wire.need(not self._claimed and self._raw is not None and self._header is not None)
        self._claimed = True  # BEFORE even the public header event, including lost writes.

    def _write(self, data):
        view = memoryview(data)
        while view:
            self._operation.checkpoint()
            engine = self._engine
            wire.need(not engine.terminal_claimed and engine.output.owned and engine.output.number == 1
                      and not engine.output.close_claimed)
            observed = os.fstat(1)
            wire.need((observed.st_dev, observed.st_ino, observed.st_mode) == engine.output.identity)
            try:
                count = os.write(1, view[:4096])
            except BlockingIOError:
                select.select([], [1], [], .05)
                continue
            wire.need(type(count) is int and 0 < count <= min(4096, len(view)))
            self._bytes += count
            wire.need(self._bytes <= TRANSFER_LIMIT)
            engine.output_bytes += count
            view = view[count:]

    def write_body(self):
        self._binding()
        wire.need(self._claimed and not self._body_done and self._bytes == 0 and self._raw is not None
                  and self._operation.source.reading and self._operation.source.material_receiving
                  and self._operation.source.reply_step == 5)
        self._write(self._header)
        self._write(self._raw)
        self._body_done = True

    def accept_custody(self, result, digest):
        self._binding()
        wire.need(self._claimed and self._body_done and not self._acknowledged and self._ack is None
                  and result == {"frameSha256": self._metadata["frameSha256"], "p12Sha256": self._metadata["p12Sha256"], "retained": True}
                  and wire.common.sha(digest))
        self._ack = digest
        self._acknowledged = True

    def retire_worker(self):
        op = self._binding()
        wire.need(op._close_claimed and op._pending is None)
        if self._worker_retired:
            wire.need(self.worker_closed() and (op._p12_assembly is None or op._p12_assembly.private_closed()))
            return
        verdict = op.guard.lifetime_ledger.verdict()
        wire.need(verdict.cleanup_complete and verdict.contained and verdict.profile_calls == 0)
        child = self._child if self._child is not None else op._p12_assembly
        if child is not None:
            wire.need(type(child) is P12AssemblyWork and child is op._p12_assembly)
            if self._child is None:
                self._child, self._raw = child, child._frame
            child.retire(self)
        else:
            wire.need(not self._claimed and self._raw is None and self._bytes == 0 and not self._acknowledged)
        self._raw = self._header = self._child = None
        self._worker_retired = True

    def worker_closed(self):
        return self._worker_retired and self._raw is None and self._header is None and self._child is None

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
