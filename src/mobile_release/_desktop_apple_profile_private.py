"""Fixed private profile input/output on the original Apple saved engine.

No additional stream, process, deadline or caller-provided output path exists.
The public terminal stays provisional until the ORIGINAL native stdout reader
has received this exact request-bound trailer and joined. These Python objects
cannot mint native custody, a save permission or an assignment.
"""
from __future__ import annotations

import hashlib
import json
import os
import select
import struct
import time

from . import apple_provisioning_api as api
from .apple_provisioning import AuthenticatedProfile, ProvisioningPlan
from .apple_provisioning_signing import MODES, PROFILE_LIMIT
from ._desktop_store_preflight_control import PREFIX, SUFFIX, HEADER_LIMIT
from ._desktop_preflight_protocol import _pairs

MAGIC = b"MRK-APPLE-PROFILE/1\n"
HEADER = struct.Struct(">I32s32s")
TRAILER_LIMIT = len(MAGIC) + HEADER.size + PROFILE_LIMIT
_ROLES = (("asc-p8", 16 * 1024), ("asc-key-id", 10), ("asc-issuer-id", 36),
          ("apple-p12", 4 * 1024 * 1024), ("apple-p12-password", 4096))


def _need(value):
    api.require(value, "profile_private_transport_refused")


def material_header(raw):
    """Five exact roles for these modes only; old Store parsers are unchanged."""
    _need(type(raw) is bytes and 0 < len(raw) <= HEADER_LIMIT and raw.endswith(b"\n"))
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: _need(False))
        _need(type(value) is dict and set(value) == {"schemaVersion", "files"}
              and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
              and type(value["files"]) is list and len(value["files"]) == len(_ROLES))
        lengths = []
        for row, (role, limit) in zip(value["files"], _ROLES):
            _need(type(row) is dict and set(row) == {"role", "bytes"} and row["role"] == role
                  and type(row["bytes"]) is int and 1 <= row["bytes"] <= limit
                  and (role not in {"asc-key-id", "asc-issuer-id"} or row["bytes"] == limit))
            lengths.append(row["bytes"])
        return tuple(lengths)
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise api.ProvisioningError("profile_private_transport_refused") from None


def receive_material(source, operation, scratch):
    """Borrow the SAME original private input, never its ordinary Store role."""
    from .build_inputs import FiniteScratch
    from .desktop_apple_provisioning import AppleProvisioningRun
    from ._desktop_apple_provisioning_control import AppleProvisioningInput
    _need(type(source) is AppleProvisioningInput and type(operation) is AppleProvisioningRun
          and operation.source is source and source.require_operation() is operation
          and operation.request.context["mode"] in MODES and operation.invocation is not None
          and operation.runtime is not None and type(scratch) is FiniteScratch
          and scratch in operation.scratches and scratch.layout == "store-selection"
          and scratch.cancellation is operation.guard and not source._material_read
          and source.material_pending and not source.material_receiving and not source.reading
          and source._profile_material is None and source._profile_parts is None)
    operation.checkpoint()
    source._material_read = True
    source.material_receiving = True
    # Each part is retained on the original input BEFORE another read/check can
    # fail. No constructor exception leaves a detached private receiver.
    source._profile_parts = []
    try:
        _need(source._take(len(PREFIX), audit=False) == PREFIX)
        raw = bytearray()
        while not raw.endswith(b"\n"):
            _need(len(raw) < HEADER_LIMIT)
            raw.extend(source._take(1, audit=False))
        for length in material_header(bytes(raw)):
            # The original source buffer stays bounded; _take consumes it and
            # polls the SAME held STOP/work endpoint between its small reads.
            source._profile_parts.append(bytes(source._take(length, audit=False)))
        _need(source._take(len(SUFFIX), audit=False) == SUFFIX)
        source._profile_material = tuple(source._profile_parts)
        source._profile_parts = None
        # Preserve a SINGLE identity-pinned three-part view for the unchanged
        # selected-P8 validator. Never replace it after a provider/extractor call.
        source._material = source._profile_material[:3]
        operation.validate_apple_shape(source._material)
        password = source._profile_material[4]
        _need(b"\0" not in password)
        password.decode("utf-8", errors="strict")
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


def profile_material(source, operation):
    from ._desktop_apple_provisioning_control import AppleProvisioningInput
    from .desktop_apple_provisioning import AppleProvisioningRun
    _need(type(source) is AppleProvisioningInput and type(operation) is AppleProvisioningRun
          and operation.source is source and source.require_operation() is operation
          and operation.request.context["mode"] in MODES and source._material_read
          and not source.close_claimed and not source.material_receiving and not source.material_pending
          and type(source._profile_material) is tuple and len(source._profile_material) == 5
          and type(source._material) is tuple and len(source._material) == 3
          and all(left is right for left, right in zip(source._material, source._profile_material[:3])))
    operation.checkpoint()
    return source._profile_material


def trailer_header(request_sha256, profile):
    """Bounded DATA framing, not an authentication/finality assertion."""
    _need(type(request_sha256) is str and api.HEX_RE.fullmatch(request_sha256) is not None
          and type(profile) is bytes and len(profile) <= PROFILE_LIMIT)
    return MAGIC + HEADER.pack(len(profile), hashlib.sha256(profile).digest(), bytes.fromhex(request_sha256))


class ProfileOutput:
    __slots__ = ("_operation", "_engine", "_request", "_profile", "_authenticated", "_claimed",
                 "_finished", "_closed", "_bytes", "_header")

    def __init__(self, operation):
        from .desktop_apple_provisioning import AppleProvisioningRun
        from ._desktop_apple_provisioning_engine import _Engine
        _need(type(operation) is AppleProvisioningRun and operation.source.require_operation() is operation
              and operation.request.context["mode"] in MODES and type(operation.source.engine) is _Engine
              and getattr(operation, "_profile_output", None) is None)
        operation.checkpoint()
        self._operation, self._engine, self._request = operation, operation.source.engine, operation.request
        self._profile = self._authenticated = self._header = None
        self._claimed = self._finished = self._closed = False
        self._bytes = 0
        operation._profile_output = self

    def retain_authenticated(self, plan, result):
        operation = self._operation
        _need(not self._claimed and self._authenticated is None and self._profile is None
              and operation._profile_output is self and operation.source.require_operation() is operation
              and self._request is operation.request and operation.request.context["mode"] in {"profile-reuse", "profile-create"}
              and type(plan) is ProvisioningPlan and type(result) is AuthenticatedProfile)
        # Keep the exact existing CMS result before any further comparison can
        # fail. The original worker still rechecks source and native disposition.
        self._authenticated = result
        self._profile = result.profile.content
        _need(type(self._profile) is bytes and 0 < len(self._profile) <= PROFILE_LIMIT
              and plan.context == operation.context and plan.target == operation.target
              and plan.binding is not None and result.key_ref == plan.binding.key_ref
              and result.certificate_sha256 == plan.binding.certificate_sha256
              and plan.profile is not None and result.profile.resource_id == plan.profile.resource_id)
        operation.checkpoint()
        verdict = operation.guard.lifetime_ledger.verdict()
        _need(verdict.cleanup_complete and verdict.contained and verdict.profile_calls == 1)

    def download_metadata(self):
        _need(self._authenticated is not None and type(self._profile) is bytes and not self._claimed)
        return {"bytes": len(self._profile), "sha256": api.digest(self._profile)}

    def _write(self, data):
        engine = self._engine
        view = memoryview(data)
        while view:
            engine.input.output_checkpoint(terminal=True)
            _need(time.monotonic() < engine.input.hard_endpoint() and engine.terminal_claimed
                  and engine.output.owned and engine.output.number == 1 and not engine.output.close_claimed)
            observed = os.fstat(1)
            _need((observed.st_dev, observed.st_ino, observed.st_mode) == engine.output.identity)
            try:
                count = os.write(1, view[:4096])
            except BlockingIOError:
                select.select([], [1], [], min(.05, max(0, engine.input.hard_endpoint() - time.monotonic())))
                continue
            _need(type(count) is int and 0 < count <= min(4096, len(view)))
            self._bytes += count
            _need(self._bytes <= TRAILER_LIMIT)
            engine.output_bytes += count
            view = view[count:]

    def terminal(self, engine, value):
        operation = self._operation
        _need(engine is self._engine and engine.service is operation and engine.input is operation.source
              and engine.request is self._request and operation._profile_output is self
              and not self._claimed and not engine.terminal_claimed and not self._closed)
        self._claimed = True  # Partial/lost terminal or trailer is never repeated.
        # Late cancellation/refusal emits an empty trailer. Even a fully
        # authenticated earlier download cannot authorize a post-cancel save.
        body = self._profile if (value["outcome"] == "complete" and value["result"] is not None
            and value["result"]["decision"] == "download-returned" and self._authenticated is not None) else b""
        _need(type(body) is bytes and (not body or operation.request.context["mode"] in {"profile-reuse", "profile-create"}))
        self._header = trailer_header(self._request.digest, body)
        engine.write(engine._response("terminal", value), terminal=True)
        self._write(self._header)
        self._write(body)
        self._finished = True

    def retire(self, engine):
        _need(engine is self._engine and engine.service is self._operation and engine.request is self._request
              and self._operation._profile_output is self)
        if self._closed:
            return
        # No output retry or byte disposal after an unknown handoff/close. The
        # existing engine retains this original if any cut remains unknown.
        _need(self._finished and self._claimed and all(slot.owned and slot.closed for slot in (engine.output, engine.error_output))
              and engine.input.material_closed() and self._operation.closed()
              and not engine.guard.lifetime_ledger.fatal)
        self._profile = self._authenticated = self._header = None
        self._closed = True

    def closed(self):
        return self._closed and self._profile is None and self._authenticated is None and self._header is None
