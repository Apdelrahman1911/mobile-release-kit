"""Fixed installed entry; native original joins still decide finality."""
from ._desktop_saved_command_control import SavedCommandDomain
from ._desktop_saved_command_engine import _SavedCommandEngine, run_engine


class _Engine(_SavedCommandEngine):
    def __init__(self, started):
        super().__init__(started, domain=SavedCommandDomain.ToolAcquisition)


def main(*, started):
    return run_engine(_Engine(started))
