"""One fixed acquisition request, using the original held saved-command pipe."""
from ._desktop_saved_command_control import SavedCommandDomain, _SavedCommandInput


class ToolAcquisitionInput(_SavedCommandInput):
    def __init__(self, started):
        super().__init__(started, domain=SavedCommandDomain.ToolAcquisition)
        self.operation = None

    def bind_operation(self, operation):
        from .desktop_tool_acquisition import ToolAcquisitionRun
        self._owner()
        self._require(type(operation) is ToolAcquisitionRun and self.operation is None
            and self.guard is not None and self.guard._saved_command_input() is self
            and operation.source is self and operation.guard is self.guard
            and self.active and self.request_returned and not self.close_claimed)
        self.operation = operation

    def require_operation(self):
        from .desktop_tool_acquisition import ToolAcquisitionRun
        self._owner()
        self._require(type(self.operation) is ToolAcquisitionRun and self.guard is not None
            and self.operation.source is self and self.operation.guard is self.guard)
        self.guard._check_owner()
        return self.operation
