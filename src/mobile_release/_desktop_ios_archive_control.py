"""Exact third saved-command input; no caller-supplied operation or runner."""
from __future__ import annotations

from ._desktop_saved_command_control import SavedCommandDomain, _SavedCommandInput


class IOSArchiveInput(_SavedCommandInput):
    def __init__(self, started: float) -> None:
        super().__init__(started, domain=SavedCommandDomain.IOSArchive)
        self.operation = None
        self._engine = None

    def bind_operation(self, operation) -> None:
        from .ios_archive_operation import IOSArchiveOperation
        self._owner()
        self._require(type(operation) is IOSArchiveOperation and self.operation is None
                      and self.guard is not None and self.guard._saved_command_input() is self
                      and operation.source is self and operation.guard is self.guard
                      and self.active and self.request_returned and not self.close_claimed)
        self.operation = operation

    def require_operation(self):
        from .ios_archive_operation import IOSArchiveOperation
        self._owner()
        self._require(type(self.operation) is IOSArchiveOperation and self.guard is not None
                      and self.operation.source is self and self.operation.guard is self.guard)
        self.guard._check_owner()
        return self.operation

    def _bind_engine(self, engine) -> None:
        from ._desktop_ios_archive_engine import _Engine
        self._owner()
        self._require(type(engine) is _Engine and self._engine is None and engine.input is self
                      and engine.domain is SavedCommandDomain.IOSArchive)
        self._engine = engine

    def progress(self, stage: str) -> None:
        from ._desktop_ios_archive_engine import _Engine
        self._owner()
        self._require(type(self._engine) is _Engine and self._engine.input is self
                      and self._engine.guard is self.guard and not self.close_claimed)
        self._engine._progress(self, stage)
