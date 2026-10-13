"""Closed artifact entry; same held-input/process/terminal finality owner."""
from __future__ import annotations

from ._desktop_saved_command_control import SavedCommandDomain
from ._desktop_saved_command_engine import _SavedCommandEngine, run_engine


class _Engine(_SavedCommandEngine):
    def __init__(self, started: float) -> None:
        super().__init__(started, domain=SavedCommandDomain.ArtifactInspection)


def main(*, started: float) -> int:
    return run_engine(_Engine(started))
