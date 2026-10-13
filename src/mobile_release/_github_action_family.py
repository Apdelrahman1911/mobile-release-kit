"""Two private fixed workflow families; not a plugin or renderer selector."""
from enum import Enum


class Family(Enum):
    PREFLIGHT = "preflight"
    RELEASE = "release"


def policy_for(family: Family):
    if family is Family.PREFLIGHT:
        from . import github_preflight
        return github_preflight
    if family is Family.RELEASE:
        from . import github_release
        return github_release
    raise ValueError("Invalid fixed GitHub workflow family")


def journal_suffix(family: Family) -> tuple[str, ...]:
    policy_for(family)
    return (".local", "share", "mobile-release-kit", "github-" + family.value)
