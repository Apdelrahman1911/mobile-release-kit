"""Explicit disposable GitHub-hosted fixture preparation; never product setup.

Only the selected Apple Xcode tree and /Applications itself may change. No
contents, symlink targets, gid, ACLs, other apps or production guards change.
"""
import json
import os
import re
import stat
import subprocess
import sys
import time

MAX_ENTRIES = 1_000_000
MAX_DEPTH = 64
MAX_PATH = 4096
SECONDS = 720
REQUIREMENT = 'identifier "com.apple.dt.Xcode" and anchor apple'
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class Refused(Exception):
    def __init__(self, condition="precondition", **facts):
        super().__init__(condition)
        self.condition = condition
        self.facts = facts


def need(value, condition="precondition", **facts):
    if not value:
        raise Refused(condition, **facts)


def point(end):
    need(time.monotonic() < end, "deadline")


def failure_facts(error):
    # Fixed categories and numeric facts only; never paths or exception text.
    if error is None:
        return None
    if isinstance(error, Refused):
        return {"kind": "precondition", "condition": error.condition, **error.facts}
    if isinstance(error, subprocess.TimeoutExpired):
        return {"kind": "command-timeout"}
    if isinstance(error, subprocess.CalledProcessError):
        return {"kind": "command-exit", "exitCode": error.returncode}
    if isinstance(error, OSError):
        return {"kind": "filesystem", "errno": error.errno}
    return {"kind": "unexpected"}


def identity(row):
    return row.st_dev, row.st_ino, stat.S_IFMT(row.st_mode)


def open_original(name, parent, directory):
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    need(stat.S_ISDIR(before.st_mode) if directory else
         stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
         "original-kind-or-links", mode=before.st_mode, links=before.st_nlink)
    fd = os.open(name, FLAGS | (os.O_DIRECTORY if directory else 0), dir_fd=parent)
    try:
        held = os.fstat(fd)
        need(identity(held) == identity(before), "original-open-identity")
        return fd
    except BaseException:
        os.close(fd)
        raise


def protect(fd):
    before = os.fstat(fd)
    need(stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
    wanted = stat.S_IMODE(before.st_mode) & ~0o7022
    if before.st_uid != 0:
        os.fchown(fd, 0, -1)  # Preserve group; never dereference a pathname.
    if stat.S_IMODE(before.st_mode) != wanted:
        os.fchmod(fd, wanted)  # Preserve all normal read/execute and owner-write bits.
    after = os.fstat(fd)
    need(identity(after) == identity(before) and after.st_uid == 0
         and after.st_gid == before.st_gid and stat.S_IMODE(after.st_mode) == wanted
         and after.st_size == before.st_size and after.st_mtime_ns == before.st_mtime_ns)


def walk(fd, end, *, mutate, path_bytes, depth=0, counts=None, device=None):
    """Physical descriptor-relative walk; one directory iterator per level."""
    point(end)
    need(depth <= MAX_DEPTH and path_bytes <= MAX_PATH, "tree-depth-or-path",
         depth=depth, pathBytes=path_bytes)
    if counts is None:
        counts = {"directories": 0, "files": 0, "symlinks": 0}
    root = os.fstat(fd)
    if device is None:
        device = root.st_dev
    need(root.st_dev == device and stat.S_ISDIR(root.st_mode), "tree-root-kind-or-device",
         sameDevice=root.st_dev == device, mode=root.st_mode)
    need(sum(counts.values()) < MAX_ENTRIES, "tree-entry-bound", entries=sum(counts.values()))
    counts["directories"] += 1
    if mutate:
        protect(fd)  # Protect a parent before touching any descendants.
    with os.scandir(fd) as entries:
        for item in entries:
            point(end)
            name = item.name
            need(name not in (".", "..") and "/" not in name, "tree-component")
            length = path_bytes + 1 + len(os.fsencode(name))
            need(length <= MAX_PATH and sum(counts.values()) < MAX_ENTRIES, "tree-path-or-entry-bound",
                 pathBytes=length, entries=sum(counts.values()))
            row = os.stat(name, dir_fd=fd, follow_symlinks=False)
            need(row.st_dev == device, "tree-entry-device", sameDevice=False)
            if stat.S_ISLNK(row.st_mode):
                counts["symlinks"] += 1  # Neither follow nor modify links.
                continue
            directory = stat.S_ISDIR(row.st_mode)
            need(directory or stat.S_ISREG(row.st_mode) and row.st_nlink == 1,
                 "tree-entry-kind-or-links", mode=row.st_mode, uid=row.st_uid,
                 gid=row.st_gid, links=row.st_nlink, depth=depth,
                 entries=sum(counts.values()))
            child = open_original(name, fd, directory)
            try:
                need(identity(os.fstat(child)) == identity(row), "tree-entry-open-identity")
                if directory:
                    walk(child, end, mutate=mutate, path_bytes=length, depth=depth + 1,
                         counts=counts, device=device)
                else:
                    counts["files"] += 1
                    if mutate:
                        protect(child)
                need(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == identity(os.fstat(child)),
                     "tree-entry-post-identity")
            finally:
                os.close(child)
    return counts


def selected(applications):
    row = os.stat("Xcode.app", dir_fd=applications, follow_symlinks=False)
    if not stat.S_ISLNK(row.st_mode):
        need(stat.S_ISDIR(row.st_mode))
        return "Xcode.app", None
    account = int(os.environ["SUDO_UID"])
    need(account > 0 and row.st_uid in (0, account) and row.st_nlink == 1 and 1 <= row.st_size <= 1024)
    target = os.readlink("Xcode.app", dir_fd=applications)
    name = target.removeprefix("/Applications/")
    need(len(os.fsencode(target)) <= 1024 and len(name) <= 255 and name != "Xcode.app"
         and re.fullmatch(r"Xcode[A-Za-z0-9._+-]*\.app", name) is not None)
    def stamp(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                value.st_nlink, value.st_size, value.st_mtime_ns)
    post = os.stat("Xcode.app", dir_fd=applications, follow_symlinks=False)
    need(stamp(post) == stamp(row))
    return name, (stamp(row), target)


def verify(path, end):
    point(end)
    subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--all-architectures",
                    "--test-requirement", "=" + REQUIREMENT, path],
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
                   cwd="/", check=True, timeout=min(240, end - time.monotonic()))


def main():
    stage = "ci-profile"
    end = time.monotonic() + SECONDS
    fds = []
    failure = None
    close_failures = 0
    counts = None
    try:
        # Accident-prevention checks, not an authorization mechanism. Only the
        # explicit reviewed workflow invokes this privileged fixture on a VM.
        need(sys.platform == "darwin" and os.geteuid() == 0 and int(os.environ["SUDO_UID"]) > 0
             and os.environ.get("GITHUB_ACTIONS") == "true"
             and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
             and os.environ.get("RUNNER_OS") == "macOS"
             and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch")
        stage = "selection"
        root = open_original("/", None, True); fds.append(root)
        applications = open_original("Applications", root, True); fds.append(applications)
        need(os.fstat(root).st_uid == os.fstat(applications).st_uid == 0
             and not os.fstat(root).st_mode & 0o7022)
        name, alias = selected(applications)
        app = open_original(name, applications, True); fds.append(app)
        contents = open_original("Contents", app, True); fds.append(contents)
        developer = open_original("Developer", contents, True); fds.append(developer)
        path = "/Applications/" + name
        def joined():
            point(end)
            need(selected(applications) == (name, alias))
            for fd, parent, leaf in ((applications, root, "Applications"), (app, applications, name),
                                     (contents, app, "Contents"), (developer, contents, "Developer")):
                need(identity(os.fstat(fd)) == identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)))
        joined()
        stage = "apple-signature-before"
        verify(path, end)
        joined()
        stage = "physical-preflight"
        before = walk(app, end, mutate=False, path_bytes=len(os.fsencode(path)))
        joined()
        stage = "protect-applications-only"
        protect(applications)  # Never walk unrelated Applications members.
        stage = "protect-selected-tree"
        counts = walk(app, end, mutate=True, path_bytes=len(os.fsencode(path)))
        need(counts == before)
        joined()
        stage = "apple-signature-after"
        verify(path, end)
        joined()
        stage = "complete"
    except BaseException as error:
        failure = error
    finally:
        # Every known original gets an independent close attempt. A close error
        # prevents success; never retry an uncertain descriptor number.
        for fd in reversed(fds):
            try:
                os.close(fd)
            except BaseException as error:
                close_failures += 1
                if failure is None:
                    failure = error
                    stage = "original-close"
    print(json.dumps({"profile": "disposable-github-hosted-protected-xcode", "stage": stage,
                      "outcome": "prepared" if failure is None else "refused",
                      "counts": counts, "failure": failure_facts(failure),
                      "closeFailures": close_failures, "defaultMacQualified": False}, sort_keys=True))
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
