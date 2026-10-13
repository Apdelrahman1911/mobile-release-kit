"""Pure release consent text shared by the Store core and Desktop policy.

This text is not authorization. The existing Store guard and authenticated
resolver still establish the protected workflow, source and original evidence.
"""
from __future__ import annotations

from .config import ReleaseVersion


def expected_confirmation(stage: str, platform: str, release: ReleaseVersion) -> str:
    return f"{stage}:{platform}:{release.name}:{release.build}"
