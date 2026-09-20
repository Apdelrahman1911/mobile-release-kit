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
