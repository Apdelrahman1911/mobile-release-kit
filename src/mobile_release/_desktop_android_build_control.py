"""Exact Android-build source; never an offline-preflight budget capability."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ._desktop_saved_command_control import SavedCommandDomain, _SavedCommandInput

if TYPE_CHECKING:
    from ._desktop_android_build_engine import _Engine
    from .android_build_operation import AndroidBuildOperation


class AndroidBuildInput(_SavedCommandInput):
    def __init__(self, started: float) -> None:
        super().__init__(started, domain=SavedCommandDomain.AndroidBuild)
        self.operation: AndroidBuildOperation | None = None
        self._engine: _Engine | None = None
        self.material = None
        self.material_pending = self.material_receiving = self.signed = False

    def _request_material(self, request) -> None:
        from ._desktop_android_build_protocol import is_signed
        self._owner()
        self.signed = is_signed(request.context)
        self.material_pending = self.signed

    def receive_material(self, operation) -> None:
        self._owner()
        self._require(self.signed and self.material_pending and not self.material_receiving
                      and self.active and self.request_returned and operation is self.require_operation()
                      and operation.signing is not None and operation.invocation is not None
                      and operation.invocation.signing_lease is None
                      and operation.invocation.project_owner is not None)
        operation.checkpoint()
        from ._desktop_android_signing_material import read_material
        self.material_receiving = True
        try:
            read_material(self, operation.request)
            self.material_pending = False
        finally:
            self.material_receiving = False
        self.guard.check()

    def close(self) -> None:
        super().close()
        if self.signed:
            self.buffer.clear()
        if self.material is not None:
            self.material.retire()

    def material_closed(self) -> bool:
        self._owner()
        return (self.closed and not self.material_receiving and not self.buffer
                and (self.material is None or self.material._retired))

    def bind_operation(self, operation: AndroidBuildOperation) -> None:
        from .android_build_operation import AndroidBuildOperation
        self._owner()
        self._require(type(operation) is AndroidBuildOperation and self.operation is None
                      and self.guard is not None and self.guard._saved_command_input() is self
                      and operation.source is self and operation.guard is self.guard
                      and self.active and self.request_returned and not self.close_claimed)
        self.operation = operation

    def require_operation(self) -> AndroidBuildOperation:
        from .android_build_operation import AndroidBuildOperation
        self._owner()
        self._require(type(self.operation) is AndroidBuildOperation and self.guard is not None
                      and self.operation.source is self and self.operation.guard is self.guard)
        self.guard._check_owner()
        return self.operation

    def _bind_engine(self, engine: _Engine) -> None:
        from ._desktop_android_build_engine import _Engine
        self._owner()
        self._require(type(engine) is _Engine and self._engine is None and engine.input is self
                      and engine.domain is SavedCommandDomain.AndroidBuild)
        self._engine = engine

    def progress(self, stage: str) -> None:
        """Only the original engine can encode a reached fixed service stage."""
        from ._desktop_android_build_engine import _Engine
        self._owner()
        self._require(type(self._engine) is _Engine and self._engine.input is self
                      and self._engine.guard is self.guard and not self.close_claimed)
        self._engine._progress(self, stage)
