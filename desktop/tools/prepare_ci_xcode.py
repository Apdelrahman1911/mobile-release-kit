"""Explicit disposable GitHub-hosted fixture preparation; never product setup.

Only the selected Apple Xcode tree and /Applications itself may change. No
file contents, symlink targets, groups, other apps or production guards change.
Hardlinked files get independent APFS clones; ACLs are copied, never erased.
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
SECONDS = 2100
SIGNATURE_SECONDS = 900
MAX_QUEUED_NAME_BYTES = 32 * 1024**2
MAX_CLONE_BYTES = 64 * 1024**3
SDK_ALIAS = ("Contents", "Developer", "Platforms", "iPhoneOS.platform", "Developer", "SDKs", "iPhoneOS.sdk")
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
    extra = {"cleanupFailures": error._cleanup_failures} if hasattr(error, "_cleanup_failures") else {}
    if isinstance(error, Refused):
        return {"kind": "precondition", "condition": error.condition, **error.facts, **extra}
    if isinstance(error, subprocess.TimeoutExpired):
        return {"kind": "command-timeout", **extra}
    if isinstance(error, subprocess.CalledProcessError):
        return {"kind": "command-exit", "exitCode": error.returncode, **extra}
    if isinstance(error, OSError):
        return {"kind": "filesystem", "errno": error.errno, **extra}
    return {"kind": "unexpected", **extra}


def identity(row):
    return row.st_dev, row.st_ino, stat.S_IFMT(row.st_mode)


def open_original(name, parent, directory, *, allow_links=False):
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    need(stat.S_ISDIR(before.st_mode) if directory else
         stat.S_ISREG(before.st_mode) and (before.st_nlink >= 1 if allow_links else before.st_nlink == 1),
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


def stamp(row):
    return (row.st_dev, row.st_ino, row.st_mode, row.st_uid, row.st_gid,
            row.st_nlink, row.st_size, row.st_mtime_ns, row.st_ctime_ns)


def native_clone():
    # Apple clonefile(2): new inode/xattrs, shared CoW data, exclusive destination.
    # CLONE_ACL also applies inherited ACLs. Nothing clears ACLs; Book still checks.
    import ctypes
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    fn = lib.fclonefileat
    fn.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    fn.restype = ctypes.c_int
    def clone(source, parent, leaf):
        if fn(source, parent, os.fsencode(leaf), 0x0001 | 0x0004) != 0:
            raise OSError(ctypes.get_errno(), "clone refused")
    return clone


def split_link(source, parent, name, end, clone):
    """Replace just this selected name; never change another hardlink's permissions."""
    import secrets
    point(end)
    original = os.fstat(source)
    need(stat.S_ISREG(original.st_mode) and original.st_nlink > 1, "clone-source")
    need(stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == stamp(original), "clone-source-name")
    temp = ".mrk-xcode-clone-" + secrets.token_hex(16)
    held = None
    created = published = transferred = False
    primary = None
    try:
        clone(source, parent, temp)  # No copy fallback or existing destination.
        created = True
        held = open_original(temp, parent, False)
        copied = os.fstat(held)
        need(copied.st_dev == original.st_dev and copied.st_ino != original.st_ino
             and copied.st_size == original.st_size and copied.st_mtime_ns == original.st_mtime_ns
             and copied.st_uid == original.st_uid and copied.st_gid == original.st_gid,
             "clone-result")
        protect(held)
        point(end)
        need(stamp(os.fstat(source)) == stamp(original)
             and stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == stamp(original), "clone-source-post")
        need(identity(os.stat(temp, dir_fd=parent, follow_symlinks=False)) == identity(os.fstat(held)), "clone-temp-post")
        os.replace(temp, name, src_dir_fd=parent, dst_dir_fd=parent)
        published = True
        need(identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(os.fstat(held))
             and os.fstat(held).st_nlink == 1, "clone-published-post")
        transferred = True
        return held
    except BaseException as error:
        primary = error
        raise
    finally:
        # No path adoption after an unestablished open or ambiguous publication.
        # The disposable hosted VM, not a guessed unlink, owns any such residue.
        cleanup_failures = 0
        try:
            if created and not published:
                need(held is not None, "clone-temporary-unestablished")
                need(identity(os.stat(temp, dir_fd=parent, follow_symlinks=False)) == identity(os.fstat(held)), "clone-temporary-changed")
                os.unlink(temp, dir_fd=parent)
        except BaseException:
            cleanup_failures += 1
        try:
            if held is not None and not transferred:
                os.close(held)
        except BaseException:
            cleanup_failures += 1
        if cleanup_failures:
            if primary is not None:
                primary._cleanup_failures = cleanup_failures
            else:
                raise Refused("clone-cleanup", cleanupFailures=cleanup_failures)


def protect_sdk_alias(parent, name, row):
    need(row.st_nlink == 1 and 1 <= row.st_size <= 1024, "sdk-alias-shape")
    target = os.readlink(name, dir_fd=parent)
    need(re.fullmatch(r"iPhoneOS[0-9]+(?:\.[0-9]+)*\.sdk", target) is not None, "sdk-alias-target")
    need(stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == stamp(row), "sdk-alias-before")
    os.chown(name, 0, -1, dir_fd=parent, follow_symlinks=False)
    post = os.stat(name, dir_fd=parent, follow_symlinks=False)
    need(identity(post) == identity(row) and post.st_uid == 0 and post.st_gid == row.st_gid
         and post.st_mode == row.st_mode and os.readlink(name, dir_fd=parent) == target, "sdk-alias-after")


def walk(fd, end, *, mutate, path_bytes, depth=0, counts=None, device=None, relative=(), clone=None, queued=None):
    """Physical walk. Freeze bounded immediate names before changing this directory."""
    point(end)
    need(depth <= MAX_DEPTH and path_bytes <= MAX_PATH, "tree-depth-or-path",
         depth=depth, pathBytes=path_bytes)
    if counts is None:
        counts = {"directories": 0, "files": 0, "symlinks": 0, "hardlinkedFiles": 0, "cloneBytes": 0}
    root = os.fstat(fd)
    if device is None:
        device = root.st_dev
    need(root.st_dev == device and stat.S_ISDIR(root.st_mode), "tree-root-kind-or-device",
         sameDevice=root.st_dev == device, mode=root.st_mode)
    need((counts["directories"] + counts["files"] + counts["symlinks"]) < MAX_ENTRIES, "tree-entry-bound", entries=(counts["directories"] + counts["files"] + counts["symlinks"]))
    counts["directories"] += 1
    if mutate:
        protect(fd)  # Protect a parent before touching any descendants.
    if queued is None:
        queued = [0]
    names = []
    try:
        with os.scandir(fd) as entries:
            for item in entries:
                point(end)
                name = item.name
                cost = len(os.fsencode(name)) + 64
                need(queued[0] + cost <= MAX_QUEUED_NAME_BYTES, "queued-names-bound")
                names.append((name, cost))
                queued[0] += cost
        while names:
            point(end)
            name, cost = names.pop()
            queued[0] -= cost
            need(name not in (".", "..") and "/" not in name, "tree-component")
            length = path_bytes + 1 + len(os.fsencode(name))
            need(length <= MAX_PATH and (counts["directories"] + counts["files"] + counts["symlinks"]) < MAX_ENTRIES, "tree-path-or-entry-bound",
                 pathBytes=length, entries=(counts["directories"] + counts["files"] + counts["symlinks"]))
            row = os.stat(name, dir_fd=fd, follow_symlinks=False)
            need(row.st_dev == device, "tree-entry-device", sameDevice=False)
            if stat.S_ISLNK(row.st_mode):
                counts["symlinks"] += 1
                if relative + (name,) == SDK_ALIAS:
                    if mutate:
                        protect_sdk_alias(fd, name, row)
                    else:
                        need(row.st_nlink == 1 and 1 <= row.st_size <= 1024
                             and re.fullmatch(r"iPhoneOS[0-9]+(?:\.[0-9]+)*\.sdk", os.readlink(name, dir_fd=fd)) is not None, "sdk-alias-preflight")
                continue  # Never follow or otherwise modify symlinks.
            directory = stat.S_ISDIR(row.st_mode)
            need(directory or stat.S_ISREG(row.st_mode) and row.st_nlink >= 1,
                 "tree-entry-kind-or-links", mode=row.st_mode, uid=row.st_uid,
                 gid=row.st_gid, links=row.st_nlink, depth=depth,
                 entries=(counts["directories"] + counts["files"] + counts["symlinks"]))
            child = open_original(name, fd, directory, allow_links=True)
            try:
                need(identity(os.fstat(child)) == identity(row), "tree-entry-open-identity")
                if directory:
                    walk(child, end, mutate=mutate, path_bytes=length, depth=depth + 1,
                         counts=counts, device=device, relative=relative + (name,), clone=clone, queued=queued)
                else:
                    counts["files"] += 1
                    if row.st_nlink > 1:
                        counts["hardlinkedFiles"] += 1
                        counts["cloneBytes"] += row.st_size
                        need(0 <= row.st_size and counts["cloneBytes"] <= MAX_CLONE_BYTES, "clone-byte-bound")
                        if mutate:
                            need(clone is not None, "clone-unavailable")
                            new = split_link(child, fd, name, end, clone)
                            old, child = child, new
                            os.close(old)  # Retired first; never retry an uncertain close.
                    if mutate:
                        protect(child)
                need(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == identity(os.fstat(child)),
                     "tree-entry-post-identity")
            finally:
                os.close(child)
    finally:
        queued[0] -= sum(cost for _, cost in names)
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
                   cwd="/", check=True, timeout=min(SIGNATURE_SECONDS, end - time.monotonic()))


def ci_profile(arguments, environment, platform, effective_uid, script):
    """Closed accident-prevention profiles, never environment-derived authority."""
    need(platform == "darwin" and effective_uid == 0 and int(environment["SUDO_UID"]) > 0
         and environment.get("GITHUB_ACTIONS") == "true"
         and environment.get("RUNNER_ENVIRONMENT") == "github-hosted"
         and environment.get("RUNNER_OS") == "macOS")
    if arguments == []:
        need(environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch")
        return
    source = environment.get("GITHUB_SHA", "")
    repository = "Apdelrahman1911/mobile-release-kit"
    ref = "refs/heads/verify/desktop-macos-candidate-consume"
    need(arguments == ["--candidate-consume"] and environment.get("GITHUB_EVENT_NAME") == "push"
         and environment.get("GITHUB_REPOSITORY") == repository and environment.get("GITHUB_REF") == ref
         and environment.get("GITHUB_WORKFLOW_REF") == repository +
             "/.github/workflows/desktop-macos-candidate-consume.yml@" + ref
         and re.fullmatch(r"[0-9a-f]{40}", source) and source != "0" * 40
         and environment.get("GITHUB_WORKFLOW_SHA") == source
         and environment.get("MRK_CANDIDATE_MODE") in ("ordinary-ios-ui", "ordinary-ios-archive-ui", "ordinary-diagnostics-ui")
         and os.path.abspath(script) == "/Users/runner/work/mobile-release-kit/mobile-release-kit/"
             ".candidate-consumer-helper/desktop/tools/prepare_ci_xcode.py", "candidate-consume-profile")


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
        ci_profile(sys.argv[1:], os.environ, sys.platform, os.geteuid(), __file__)
        clone = native_clone()  # Resolve the supported API before any fixture mutation.
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
        counts = walk(app, end, mutate=True, path_bytes=len(os.fsencode(path)), clone=clone)
        need(all(counts[key] == before[key] for key in ("directories", "files", "symlinks"))
             and counts["hardlinkedFiles"] <= before["hardlinkedFiles"] and counts["cloneBytes"] <= before["cloneBytes"], "tree-quote-post")
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
