"""Fixed local execute entry on the original saved-command engine."""
from ._desktop_saved_command_control import SavedCommandDomain
from ._desktop_saved_command_engine import _SavedCommandEngine,run_engine
class _Engine(_SavedCommandEngine):
    def __init__(self,started):
        super().__init__(started,domain=SavedCommandDomain.LocalStoreExecute)
        self.input._bind_engine(self)
    def local_event(self,kind,payload):
        self._require(self.service is self.input.require_operation() and self.service.request is self.request)
        self.write(self._response(kind,payload))
def main(*,started):return run_engine(_Engine(started))
