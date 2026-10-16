"""Fixed private-input adapter on the existing saved-command owner."""
from __future__ import annotations

import json
import select
from ._desktop_saved_command_control import SavedCommandDomain, _SavedCommandInput
from ._desktop_store_preflight_protocol import require, _pairs, integer

PREFIX = b"MRK-STORE-MATERIAL/1\n"
SUFFIX = b"\nMRK-STORE-MATERIAL-END\n"
HEADER_LIMIT, MATERIAL_LIMIT = 1024, 16 * 1024


def parse_header(raw: bytes) -> int:
    require(type(raw) is bytes and 0 < len(raw) <= HEADER_LIMIT and raw.endswith(b"\n"))
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
                           parse_constant=lambda _: require(False))
        require(type(value) is dict and set(value) == {"schemaVersion", "files"}
                and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
                and type(value["files"]) is list and len(value["files"]) == 1)
        row = value["files"][0]
        require(type(row) is dict and set(row) == {"role", "bytes"}
                and row["role"] == "google-service-account"
                and integer(row["bytes"], MATERIAL_LIMIT, 1))
        return row["bytes"]
    except (ValueError, TypeError, UnicodeError, RecursionError):
        require(False)


class StorePreflightInput(_SavedCommandInput):
    def __init__(self, started: float) -> None:
        super().__init__(started, domain=SavedCommandDomain.LocalStorePreflight)
        self.operation = None
        self.material_pending = self.material_receiving = False
        self._material = None
        self._material_read = False

    def _request_material(self, request) -> None:
        self._owner()
        self._require(not self.material_pending and not self._material_read)
        self.material_pending = True

    def bind_operation(self, operation) -> None:
        from .desktop_store_preflight import StorePreflightRun
        self._owner()
        self._require(type(operation) is StorePreflightRun and self.operation is None
                      and self.guard is not None and self.guard._saved_command_input() is self
                      and operation.source is self and operation.guard is self.guard
                      and self.active and self.request_returned and not self.close_claimed)
        self.operation = operation

    def require_operation(self):
        from .desktop_store_preflight import StorePreflightRun
        self._owner()
        self._require(type(self.operation) is StorePreflightRun and self.guard is not None
                      and self.operation.source is self and self.operation.guard is self.guard)
        self.guard._check_owner()
        return self.operation

    def receive_material(self, operation, scratch):
        from .build_inputs import FiniteScratch
        self._owner()
        self._require(operation is self.require_operation() and operation.invocation is not None
                      and operation.runtime is not None and type(scratch) is FiniteScratch
                      and scratch in operation.scratches and scratch.layout == "store-selection"
                      and scratch.cancellation is self.guard and not self._material_read
                      and self.material_pending and not self.material_receiving)
        operation.checkpoint()
        self._material_read = True  # One attempt, including incomplete input.
        self.material_receiving = True

        def take(length):
            data = bytearray()
            while len(data) < length:
                self.guard.check()
                self._require(self.fd is not None)
                if not self.buffer:
                    try:
                        select.select([self.fd], [], [], 0.05)
                    except (OSError, ValueError) as error:
                        self.stop(); self.guard._abort(error)
                        raise
                    continue
                count = min(length - len(data), len(self.buffer))
                data.extend(self.buffer[:count]); del self.buffer[:count]
            return bytes(data)

        try:
            self._require(take(len(PREFIX)) == PREFIX)
            header = bytearray()
            while not header.endswith(b"\n"):
                self._require(len(header) < HEADER_LIMIT)
                header.extend(take(1))
            self._material = take(parse_header(bytes(header)))
            self._require(take(len(SUFFIX)) == SUFFIX)
            operation.validate_material_shape(self._material)
            snapshot = scratch.put("google-adc", self._material)
            self.material_pending = False
        finally:
            self.material_receiving = False
        self.guard.check()  # Subsequent byte or EOF is ordinary STOP.
        return snapshot

    def close(self) -> None:
        super().close()
        if self.operation is not None:
            self._require(self.operation.closed())
        self.buffer.clear()
        self._material = None  # No process-wide secure-erasure claim.

    def material_closed(self) -> bool:
        self._owner()
        return self.closed and not self.material_receiving and not self.buffer and self._material is None
