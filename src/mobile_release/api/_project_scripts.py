"""Hints from the snapshot's already bounded, closed project-file reads.

No filesystem/command lookup happens here. A name, shebang and POSIX mode are
only hints for an explicit draft edit, never execution or source approval.
"""
from __future__ import annotations

import os
import stat
from typing import Any

from .contracts import assurance

MAX_SCRIPT_CANDIDATES = 16
SCRIPT_DIRECTORIES = frozenset({
    "", "scripts", "app", "app/scripts", "androidApp", "androidApp/scripts",
    "composeApp", "composeApp/scripts", "shared", "shared/scripts",
    "ios", "ios/scripts", "iosApp", "iosApp/scripts",
})
SCRIPT_NAMES = {
    "prepare.sh": "prepare", "prepare-ios.sh": "prepare",
    "generate.sh": "prepare", "generate-project.sh": "prepare",
    "check.sh": "check", "preflight.sh": "check", "check-project.sh": "check",
    "check-android-artifact.sh": "check", "check-ios-artifact.sh": "check",
    "build.sh": "build", "build-android.sh": "build", "build-ios.sh": "build",
}
SHEBANGS = {"#!/bin/sh": "sh", "#!/bin/bash": "bash"}


def conventional_script(relative: str) -> bool:
    directory, _, name = relative.rpartition("/")
    return not relative.startswith("/") and directory in SCRIPT_DIRECTORIES and name in SCRIPT_NAMES


def process_access_identity() -> tuple[int, frozenset[int]] | None:
    """Process metadata only; not access(), ACL probing or an execution test."""
    if os.name != "posix":
        return None
    try:
        groups = os.getgroups()
        if len(groups) > 1024:
            return None
        return os.geteuid(), frozenset([os.getegid(), *groups])
    except (AttributeError, OSError):
        return None


def _executable(mode: int, uid: int, gid: int, identity: tuple[int, frozenset[int]]) -> bool:
    current, groups = identity
    # Even root needs an executable bit. This does not prove mount/ACL or
    # interpreter availability; the existing execution owner rechecks later.
    if current == 0:
        return bool(mode & 0o111)
    return bool(mode & (0o100 if uid == current else 0o010 if gid in groups else 0o001))


def project_script_hints(sources: dict[str, str], modes: dict[str, tuple[int, int, int]],
                         hints: dict[str, Any], *, partial: bool,
                         identity: tuple[int, frozenset[int]] | None) -> dict[str, Any]:
    """Only public relative names and fixed classifications leave this function.

    ``modes`` is copied from the SAME reader's final metadata receipt after its
    close returns. Other platforms/readers omit it instead of inventing rights.
    """
    android = hints.get("android", {})
    candidates = android.get("candidates", []) if isinstance(android, dict) else []
    builds = ([android.get("buildFile")] if isinstance(android, dict) else []) + [
        row.get("buildFile") for row in candidates if isinstance(row, dict)]
    ios = hints.get("ios", {})
    platforms = []
    if any(isinstance(path, str) and path in sources for path in builds):
        platforms.append("android")
    if isinstance(ios, dict) and any(ios.get(key) for key in ("projects", "workspaces", "generatedProjectSources")):
        platforms.append("ios")
    paths = sorted(path for path in sources if conventional_script(path))
    rows = []
    for path in paths[:MAX_SCRIPT_CANDIDATES]:
        # Do not return arbitrary shebangs, arguments, comments or script text.
        first_line = sources[path][:128].partition("\n")[0]
        shell = SHEBANGS.get(first_line)
        mode = modes.get(path)
        if mode is None or identity is None:
            status = "permissions-unavailable"
        elif not stat.S_ISREG(mode[0]) or stat.S_IMODE(mode[0]) & 0o7022:
            status = "unsupported-mode"
        elif not _executable(*mode, identity):
            status = "not-executable"
        elif shell is None:
            status = "unsupported-shebang"
        else:
            status = "direct-candidate"
        rows.append({"path": path, "purposeHint": SCRIPT_NAMES[path.rpartition("/")[2]],
                     "status": status, "shell": shell})
    return {"schemaVersion": 1, "scope": "project-script-hints", "coverage": "conventional-paths-only",
            "sourcePartial": partial, "truncated": len(paths) > MAX_SCRIPT_CANDIDATES,
            "platforms": platforms, "candidates": rows, "assurance": assurance("static-text")}
