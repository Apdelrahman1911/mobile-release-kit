"""Compatibility entry for the original offline-preflight child engine.

Its exact input/service/protocol and 1800/1810-second domain are unchanged.
Native original joins still decide finality, never the provisional terminal.
"""
from __future__ import annotations

# Preserve the existing module entry names and fixed offline imports.
import os
import select
import stat
import sys
import time
from dataclasses import dataclass

from ._desktop_preflight_control import PreflightInput
from ._desktop_preflight_protocol import (FINALITY_SECONDS, PROFILES, RESPONSE_LIMIT, WORK_SECONDS,
    PreflightRequest, ProtocolError, require, response)
from ._desktop_saved_command_control import SavedCommandDomain
from ._desktop_saved_command_engine import _RETAINED, _Output, _SavedCommandEngine, run_engine
from .cancellation import CleanupScope, DefaultCancellation
from .desktop_preflight import OfflinePreflightRun
from .owned_process import ProcessCleanupError


class _Engine(_SavedCommandEngine):
    def __init__(self, started: float) -> None:
        super().__init__(started, domain=SavedCommandDomain.OfflinePreflight)


def main(*, started: float) -> int:
    return run_engine(_Engine(started))
