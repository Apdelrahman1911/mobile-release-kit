"""Cooperative work deadline shared by one complete artifact inspection.

Check between bounded reads, parsing chunks and native commands. This cannot
preempt an already-running OS call; native children retain their own timeouts.
Never use this monotonic work clock as a signing-validity or provenance date.
"""
from __future__ import annotations

import time

from .errors import ValidationError

MAX_INSPECTION_SECONDS = 15 * 60


class InspectionDeadline:
    def __init__(self) -> None:
        self._expires_at = time.monotonic() + MAX_INSPECTION_SECONDS

    def check(self) -> None:
        if time.monotonic() >= self._expires_at:
            raise ValidationError("iOS artifact inspection exceeded its shared time bound; no new authorization is permitted")
