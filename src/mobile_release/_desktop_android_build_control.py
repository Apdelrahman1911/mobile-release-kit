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
        self.candidate_input = None
        self.material_pending = self.material_receiving = self.signed = False

    def _request_material(self, request) -> None:
        from ._desktop_android_build_protocol import is_signed
        self._owner()
        self.signed = is_signed(request.context)
        self.material_pending = self.signed
        from ._desktop_android_build_protocol import candidate_create
        if candidate_create(request.context):
            from ._desktop_candidate_input_control import CandidateCreateInput
            CandidateCreateInput(self,request)
            self.material_pending=False

    def request(self):
        request=super().request()
        if self.candidate_input is not None:self.candidate_input.acquire()
        return request

    def hard_endpoint(self):
        self._owner()
        end=self.candidate_input.hard_end if self.candidate_input is not None else self.work_end+10
        return min(end,self.first_failure+10) if self.first_failure is not None else end

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
        first=None
        try:
            super().close()
            if self.signed:self.buffer.clear()
            if self.material is not None:self.material.retire()
        except BaseException as error:first=error
        if self.candidate_input is not None:
            try:self.candidate_input.close()
            except BaseException as error:
                self.guard._abort(error)
                if first is None:first=error
        if first is not None:raise first

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

    def command_limits(self, timeout: int, capture: bool, output_limit: int) -> tuple[int, int]:
        operation = self.require_operation()
        candidate = getattr(operation, "_local_composition", None)
        if candidate is not None and candidate._source_pending is not None:
            from .local_release_candidate import LocalAndroidCandidateComposition
            self._require(type(candidate) is LocalAndroidCandidateComposition
                          and candidate.run.source is self and operation._pending is None)
            return candidate._source_limits(self.remaining_timeout(timeout), capture, output_limit)
        return super().command_limits(timeout, capture, output_limit)

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
