"""Read-only fixed CLT metadata preparation for the disposable macOS CI job.

This does not select tools, execute Git, create a ToolBinding or qualify a native
owner. The workflow performs one reviewed xcode-select operation afterwards;
the unchanged production lookup must still admit and execute the real CLT Git.
"""
from __future__ import annotations

import os
import stat
import sys


DIRECTORIES = (
    ("root", "/"),
    ("library", "/Library"),
    ("developer", "/Library/Developer"),
    ("clt", "/Library/Developer/CommandLineTools"),
    ("usr", "/Library/Developer/CommandLineTools/usr"),
    ("bin", "/Library/Developer/CommandLineTools/usr/bin"),
)
GIT = "/Library/Developer/CommandLineTools/usr/bin/git"


class SetupError(Exception):
    pass


def validate_host(environment: dict[str, str], system: str, machine: str, uid: int) -> None:
    required = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64", "MRK_DESKTOP_PLATFORM": "macos",
        "MRK_DESKTOP_HOSTED_CHECKS": "environment-diagnostics-native-v1"}
    if not (system == "Darwin" and machine == "arm64" and type(uid) is int and uid > 0
            and all(environment.get(key) == value for key, value in required.items())):
        raise SetupError("CLT preparation requires the disposable non-root macOS ARM64 job")


def validate_directory(value: os.stat_result, stage: str) -> None:
    # Same macOS directory predicate as the production installed-tool lookup.
    if not stat.S_ISDIR(value.st_mode):
        reason = "directory-kind"
    elif value.st_uid != 0:
        reason = "directory-owner"
    elif value.st_mode & 0o002:
        reason = "directory-world-write"
    elif value.st_mode & 0o020 and value.st_gid not in {0, 80}:
        reason = "directory-group-write"
    else:
        return
    raise SetupError(f"Installed CLT {stage}: {reason}")


def validate_git(value: os.stat_result) -> None:
    if not (stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1
            and value.st_mode & 0o100 and not value.st_mode & 0o6022 and value.st_size > 0):
        raise SetupError("Installed CLT Git: executable metadata is not admitted")


def inspect_installed(environment: dict[str, str], system: str, machine: str, uid: int) -> None:
    validate_host(environment, system, machine, uid)
    # Validate each ancestor before reading any child; never follow a substituted
    # directory merely to collect more metadata. No recursive scan or path input.
    for stage, path in (*DIRECTORIES, ("git", GIT)):
        try:
            value = os.lstat(path)
        except OSError:
            raise SetupError(f"Installed CLT {stage}: metadata unavailable") from None
        if stage == "git":
            validate_git(value)
        else:
            validate_directory(value, stage)


if __name__ == "__main__":
    try:
        if sys.platform != "darwin":
            raise SetupError("CLT preparation is macOS-only")
        host = os.uname()
        inspect_installed(dict(os.environ), host.sysname, host.machine, os.geteuid())
    except SetupError as error:
        raise SystemExit(str(error)) from None
    print("Installed root-owned CLT metadata accepted; native Git execution is still required.")
