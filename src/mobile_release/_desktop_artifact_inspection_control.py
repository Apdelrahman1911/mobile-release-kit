"""One fixed inspection request over the existing original saved-command input."""
from __future__ import annotations

from ._desktop_saved_command_control import SavedCommandDomain, _SavedCommandInput


class ArtifactInspectionInput(_SavedCommandInput):
    def __init__(self, started: float) -> None:
        super().__init__(started, domain=SavedCommandDomain.ArtifactInspection)
        self.operation = None

    def bind_operation(self, operation) -> None:
        from .desktop_artifact_inspection import ArtifactInspectionOperation
        self._owner()
        self._require(type(operation) is ArtifactInspectionOperation and self.operation is None
                      and self.guard is not None and self.guard._saved_command_input() is self
                      and operation.source is self and operation.guard is self.guard
                      and self.active and self.request_returned and not self.close_claimed)
        self.operation = operation

    def require_operation(self):
        from .desktop_artifact_inspection import ArtifactInspectionOperation
        self._owner()
        self._require(type(self.operation) is ArtifactInspectionOperation and self.guard is not None
                      and self.operation.source is self and self.operation.guard is self.guard)
        self.guard._check_owner()
        return self.operation
