"""Compatibility entry for the original saved offline-preflight input type.

The held-pipe lifecycle is shared only with the fixed Android-build domain.
OfflinePreflightBudget and existing callers still require this exact type.
"""
from __future__ import annotations

# Keep the original module's fixed imports available to its existing callers.
import math
import os
import select
import stat
import threading
import time
from typing import TYPE_CHECKING

from ._desktop_preflight_protocol import (PreflightRequest, ProtocolError, REQUEST_LIMIT,
    WORK_SECONDS, parse_request, require)
from ._desktop_saved_command_control import SavedCommandDomain, _SavedCommandInput

if TYPE_CHECKING:
    from .cancellation import DefaultCancellation


class PreflightInput(_SavedCommandInput):
    def __init__(self, started: float) -> None:
        super().__init__(started, domain=SavedCommandDomain.OfflinePreflight)
        self.budget = None
