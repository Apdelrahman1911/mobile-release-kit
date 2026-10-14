#!/usr/bin/env python3
"""Credential-free native DMG experiment; never qualifies a release image."""
import ast
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tempfile
import time

BASE = "8cece2415d245e13ddf1ef61e8d371d27ade6a4f"
BRANCH = "refs/heads/verify/desktop-macos-dmg-attributes"
IDENTIFIER = "dev.mobile-release-kit.desktop"
IMAGE_LIMIT = 32 * 1024 * 1024
NAME_LIMIT = 4096
KNOWN_NAMES = {
    b"com.apple.FinderInfo": "finder-info",
    b"com.apple.ResourceFork": "resource-fork",
    b"com.apple.quarantine": "quarantine",
    b"com.apple.diskimages.recentcksum": "diskimage-checksum",
    b"com.apple.metadata:kMDItemWhereFroms": "download-origin",
    b"com.apple.cs.CodeDirectory": "code-directory",
    b"com.apple.cs.CodeRequirements": "code-requirements",
    b"com.apple.cs.CodeSignature": "code-signature",
}
STAGER_SHA256 = "da4cb87ca73f7086ac00ded23359faaf5a305e0ab934136f3cfb3da0586788bf"


class Refused(Exception):
    pass


def need(ok, reason):
    if not ok:
        raise Refused(reason)


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def names_summary(raw):
    need(type(raw) is bytes and 0 < len(raw) <= NAME_LIMIT and raw.endswith(b"\0"), "attribute-list-shape")
    names = raw[:-1].split(b"\0")
    need(all(0 < len(name) <= 255 for name in names) and len(names) == len(set(names)), "attribute-list-shape")
    return {"knownCategories": sorted(KNOWN_NAMES[n] for n in names if n in KNOWN_NAMES),
            "unknownCount": sum(n not in KNOWN_NAMES for n in names), "nameCount": len(names)}


def xattrs(fd, call):
    ctypes.set_errno(0)
    count = call(fd, None, 0, 0)
    error = ctypes.get_errno()  # Capture this query, not a later library operation.
    if count < 0:
        return {"outcome": "query-error", "errno": error if 0 < error <= 65535 else None}
    if count == 0:
        return {"outcome": "none", "errno": None}
    row = {"outcome": "attributes-present", "errno": None}
    if count > NAME_LIMIT:
        row["listState"] = "over-bound"
        return row
    buffer = ctypes.create_string_buffer(count)
    got = call(fd, buffer, count, 0)
    need(got == count, "attribute-list-changed")
    row.update(names_summary(buffer.raw))
    row["listState"] = "observed"
    return row


def production_policy(root):
    """Use only exact original passive definitions, never import the stager."""
    raw = (root / "desktop/tools/stage_macos_installed.py").read_bytes()
    need(hashlib.sha256(raw).hexdigest() == STAGER_SHA256, "policy-source-pin")
    tree = ast.parse(raw)
    selected = [node for node in tree.body if
                (isinstance(node, ast.ClassDef) and node.name == "Refused") or
                (isinstance(node, ast.FunctionDef) and node.name in ("need", "no_xattrs"))]
    need(len(selected) == 3, "policy-source-definitions")
    space = {"sys": sys, "os": os, "_DARWIN_XATTRS": None}
    exec(compile(ast.Module(body=selected, type_ignores=[]), "<pinned-original-policy>", "exec"), space)
    return space


def sample(fd, path, call, policy, boundary, expected=None):
    before = identity(os.fstat(fd))
    need(before == identity(os.stat(path, follow_symlinks=False)), "image-original-binding")
    need(stat.S_ISREG(before[2]) and before[3:6] == (os.getuid(), os.getgid(), 1)
         and 0 < before[6] <= IMAGE_LIMIT, "image-original-shape")
    if expected is not None:
        need(before[:8] == expected[:8], "image-readonly-boundary-changed")
    observed = xattrs(fd, call)
    try:
        policy["no_xattrs"](fd)
        policy_result = "accepted"
    except policy["Refused"] as exc:
        need(type(exc) is policy["Refused"] and exc.args == ("file-extended-attributes",), "policy-unexpected-refusal")
        policy_result = "refused-file-extended-attributes"
    h = hashlib.sha256()
    offset = 0
    while offset < before[6]:
        body = os.pread(fd, min(1048576, before[6] - offset), offset)
        need(bool(body), "image-short-read")
        h.update(body)
        offset += len(body)
    need(not os.pread(fd, 1, before[6]), "image-extra-read")
    need(before == identity(os.fstat(fd)) == identity(os.stat(path, follow_symlinks=False)), "image-sample-changed")
    return {"boundary": boundary, "bytes": before[6], "sha256": h.hexdigest(),
            "mode": oct(stat.S_IMODE(before[2])), "originalBindingKnown": True,
            "ctimeChangedSincePriorBoundary": expected is not None and before[8] != expected[8],
            "productionFullIdentityWouldAccept": expected is None or before == expected,
            "xattrs": observed, "existingZeroAttributePolicy": policy_result}, before


def original(path):
    return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)


def retire(scratch, root_identity):
    # No recursive deletion, glob, shared-cache cleanup, attachment or daemon stop.
    need(identity(os.stat(scratch, follow_symlinks=False))[:2] == root_identity[:2], "cleanup-root-changed")
    need(set(os.listdir(scratch)) <= {"source", "MobileReleaseKit.dmg"}, "cleanup-root-roster")
    image = scratch / "MobileReleaseKit.dmg"
    if os.path.lexists(image):
        s = os.stat(image, follow_symlinks=False)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1, "cleanup-image-shape")
        image.unlink()
    folder = scratch / "source"
    if os.path.lexists(folder):
        s = os.stat(folder, follow_symlinks=False)
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid(), "cleanup-source-shape")
        need(set(os.listdir(folder)) <= {"README.txt"}, "cleanup-source-roster")
        leaf = folder / "README.txt"
        if os.path.lexists(leaf):
            s = os.stat(leaf, follow_symlinks=False)
            need(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1, "cleanup-source-file")
            leaf.unlink()
        folder.rmdir()
    scratch.rmdir()


def native_run():
    root = Path(__file__).resolve().parents[2]
    report = {"schemaVersion": 1, "kind": "credential-free-dmg-attribute-experiment",
              "comparisonBase": BASE, "source": os.environ.get("GITHUB_SHA"),
              "run": os.environ.get("GITHUB_RUN_ID"), "attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
              "platform": "macos-26", "machine": platform.machine(), "boundaries": [], "calls": [],
              "experimentPassed": False, "taskOutputsRetired": False,
              "developerIdQualified": False, "notarizationQualified": False, "productReady": False,
              "systemServiceExitClaimed": False, "rawNamesOrValuesEmitted": False}
    scratch = None
    held = None
    original_calls_closed = True
    synchronous_workload_known = True
    deadline = time.monotonic() + 400

    def run(role, args, timeout):
        nonlocal original_calls_closed, synchronous_workload_known
        remaining = deadline - time.monotonic()
        need(remaining > 0, "experiment-deadline")
        row = {"role": role, "entered": False, "returned": False, "returncode": None}
        report["calls"].append(row)
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, close_fds=True, cwd=scratch,
                                 env={"PATH": "/usr/bin:/bin", "HOME": str(scratch), "TMPDIR": str(scratch)})
        row["entered"] = True
        original_calls_closed = False
        try:
            code = child.wait(timeout=min(timeout, remaining))
        except subprocess.TimeoutExpired:
            synchronous_workload_known = False  # Joining only the child cannot settle timed-out helper work.
            child.kill()  # Only this original child; no process census or service stop.
            try:
                code = child.wait(timeout=5)
                row.update(returned=True, returncode=code)
                original_calls_closed = True
            except subprocess.TimeoutExpired:
                raise Refused("original-call-close-unknown")
            raise Refused("original-call-timeout")
        row.update(returned=True, returncode=code)
        original_calls_closed = True
        if code != 0:
            synchronous_workload_known = False
        need(code == 0, "native-operation-nonzero")

    try:
        need(sys.platform == "darwin" and platform.machine() == "arm64"
             and os.environ.get("GITHUB_ACTIONS") == "true"
             and os.environ.get("GITHUB_REF") == BRANCH, "native-fixture-context")
        policy = production_policy(root)
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        call = library.flistxattr
        call.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        call.restype = ctypes.c_ssize_t
        scratch = Path(tempfile.mkdtemp(prefix="mrk-dmg-attributes-", dir=os.environ["RUNNER_TEMP"]))
        root_identity = identity(os.stat(scratch, follow_symlinks=False))
        need(stat.S_IMODE(root_identity[2]) == 0o700 and root_identity[3] == os.getuid(), "scratch-owner")
        folder = scratch / "source"
        folder.mkdir(mode=0o700)
        with (folder / "README.txt").open("xb") as f:
            f.write(b"Mobile Release Kit inert, credential-free toolchain fixture.\n")
        image = scratch / "MobileReleaseKit.dmg"
        run("create", ["/usr/bin/hdiutil", "create", "-srcfolder", str(folder), "-fs", "HFS+",
                       "-format", "UDZO", "-volname", "MobileReleaseKit", str(image)], 180)
        fd = original(image)
        try:
            row, _ = sample(fd, image, call, policy, "created")
            report["boundaries"].append(row)
        finally:
            os.close(fd)
        run("sign-ad-hoc", ["/usr/bin/codesign", "--sign", "-", "--timestamp=none",
                            "--identifier", IDENTIFIER, str(image)], 60)
        # As in production: acquire original only after authorized signing.
        held = original(image)
        row, before = sample(held, image, call, policy, "signed")
        report["boundaries"].append(row)
        os.fchmod(held, 0o444)
        os.fsync(held)
        after = identity(os.fstat(held))
        need(after[:2] == before[:2] and after[3:8] == before[3:8]
             and after[2] == stat.S_IFREG | 0o444, "mode-transition")
        row, expected = sample(held, image, call, policy, "readonly", after)
        need(row["sha256"] == report["boundaries"][-1]["sha256"], "mode-transition-bytes")
        report["boundaries"].append(row)
        run("verify-signature", ["/usr/bin/codesign", "--verify", "--strict", "--test-requirement",
                                 '=identifier "' + IDENTIFIER + '"', str(image)], 60)
        row, _ = sample(held, image, call, policy, "signature-verified", expected)
        report["boundaries"].append(row)
        run("verify-image", ["/usr/bin/hdiutil", "verify", str(image)], 120)
        row, _ = sample(held, image, call, policy, "image-verified", expected)
        report["boundaries"].append(row)
        report["experimentPassed"] = True  # An observed policy refusal is a valid experiment, not a product pass.
    except Refused as exc:
        report["failure"] = {"type": "Refused", "reason": exc.args[0]}
    except Exception as exc:
        report["failure"] = {"type": "other", "reason": "unexpected-experiment-error"}
    finally:
        if held is not None:
            os.close(held)
        report["originalCallsClosed"] = original_calls_closed
        report["synchronousWorkloadKnown"] = synchronous_workload_known
        report["taskOutputsRetainedAfterUnknownWorkload"] = scratch is not None and not synchronous_workload_known
        if scratch is not None and original_calls_closed and synchronous_workload_known:
            try:
                retire(scratch, root_identity)
                report["taskOutputsRetired"] = True
            except Exception:
                report["experimentPassed"] = False
                report["cleanupFailure"] = "task-output-retirement-refused"
        raw = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
        need(len(raw) <= 65536, "public-result-bound")
        with (root / "macos-dmg-attribute-result.json").open("xb") as f:
            f.write(raw)
        print(json.dumps({"experimentPassed": report["experimentPassed"],
                          "taskOutputsRetired": report["taskOutputsRetired"],
                          "productReady": False}))
    return 0 if report["experimentPassed"] and report["taskOutputsRetired"] else 1


def self_test():
    # One focused pure parser check protects public finite output and strict bounds.
    row = names_summary(b"com.apple.FinderInfo\0private-example-not-emitted\0")
    assert row == {"knownCategories": ["finder-info"], "unknownCount": 1, "nameCount": 2}
    for invalid in (b"", b"missing-terminal", b"\0", b"a\0a\0", b"x" * 256 + b"\0", b"x" * 4096 + b"\0"):
        try:
            names_summary(invalid)
        except Refused:
            pass
        else:
            raise AssertionError("malformed-list-accepted")
    assert "private-example" not in json.dumps(row)
    assert xattrs(0, lambda *args: 0) == {"outcome": "none", "errno": None}
    def failed(*args):
        ctypes.set_errno(errno.EBADF)
        return -1
    assert xattrs(0, failed) == {"outcome": "query-error", "errno": errno.EBADF}
    names = b"com.apple.FinderInfo\0"
    def present(fd, buffer, size, options):
        if buffer is not None:
            ctypes.memmove(buffer, names, len(names))
        return len(names)
    assert xattrs(0, present) == {"outcome": "attributes-present", "errno": None,
                                "knownCategories": ["finder-info"], "unknownCount": 0,
                                "nameCount": 1, "listState": "observed"}
    print("PASS: bounded finite-name parser and zero/error/positive query classification; no native operation executed")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        raise SystemExit(self_test())
    need(sys.argv[1:] == [], "arguments")
    raise SystemExit(native_run())
