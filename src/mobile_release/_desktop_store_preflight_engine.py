"""Fixed local Store entry; the original saved-command engine owns finality."""
from ._desktop_saved_command_control import SavedCommandDomain
from ._desktop_saved_command_engine import _SavedCommandEngine, run_engine


class _Engine(_SavedCommandEngine):
    def __init__(self, started: float) -> None:
        super().__init__(started, domain=SavedCommandDomain.LocalStorePreflight)


def main(*, started: float) -> int:
    return run_engine(_Engine(started))
