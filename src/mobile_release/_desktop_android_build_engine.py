"""Fixed Android-build engine entry; no CLI, profile or runtime fallback."""
from __future__ import annotations

from ._desktop_saved_command_control import SavedCommandDomain
from ._desktop_saved_command_engine import _RETAINED, _Output, _SavedCommandEngine, run_engine


class _Engine(_SavedCommandEngine):
    def __init__(self, started: float) -> None:
        super().__init__(started, domain=SavedCommandDomain.AndroidBuild)


def main(*, started: float) -> int:
    return run_engine(_Engine(started))
