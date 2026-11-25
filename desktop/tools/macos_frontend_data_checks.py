#!/usr/bin/env python3
"""Four fixed credential/frontend DATA suites, not ordinary Mac UI evidence."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

SUITES = ("tests/asset-session.test.mjs", "tests/ios-archive.test.mjs",
          "tests/catalog.test.mjs", "tests/metadata-images.test.mjs")
OUTPUT_LIMIT = 1024 * 1024
NETWORK_POLICY = "(version 1)(allow default)(deny network*)"


def tap_counts(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= OUTPUT_LIMIT:
        raise ValueError("frontend-output-bound")
    text = raw.decode("utf-8", "strict")
    counts = {}
    for name in ("tests", "pass", "fail", "cancelled", "skipped", "todo"):
        matches = re.findall(r"^# " + name + r" ([0-9]{1,8})$", text, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError("frontend-ambiguous-summary")
        counts[name] = int(matches[0])
    return counts


def counts_pass(counts):
    return (counts["tests"] >= 151 and counts["pass"] == counts["tests"]
            and all(counts[name] == 0 for name in ("fail", "cancelled", "skipped", "todo")))


def returned_result(result):
    return (type(result) is subprocess.CompletedProcess and type(result.returncode) is int
            and type(result.stdout) is bytes and type(result.stderr) is bytes
            and len(result.stdout) + len(result.stderr) <= OUTPUT_LIMIT)


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def read_binding(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
                or not 0 < before.st_size <= 65536):
            raise ValueError("frontend-binding-file-shape")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(65537)
        if (len(raw) != before.st_size or identity(before) != identity(os.fstat(fd))
                or identity(before) != identity(path.lstat())):
            raise ValueError("frontend-binding-file-changed")
        return json.loads(raw)
    finally:
        os.close(fd)


def publish(work, name, data, limit):
    if type(data) is not bytes or len(data) > limit:
        raise ValueError("frontend-publication-bound")
    fd = os.open(work / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def main():
    if (sys.platform != "darwin" or os.getuid() == 0 or os.getuid() != os.geteuid()
            or len(sys.argv) != 1 or not sys.flags.isolated or not sys.flags.no_site):
        raise ValueError("fixed-hosted-Mac-DATA-scope")
    work, checkout = Path(os.environ["MRK_MACOS_WORK"]), Path(os.environ["GITHUB_WORKSPACE"])
    if (checkout != Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
            or work.parent != Path("/Users/runner/work/_temp")
            or not work.name.startswith("mrk-macos-aqua.")):
        raise ValueError("fixed-original-work-path")
    s = work.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
        raise ValueError("private-original-work")
    binding = read_binding(work / "source-binding.json")
    if (binding["source"] != os.environ["GITHUB_SHA"]
            or binding["workflowSource"] != os.environ["GITHUB_WORKFLOW_SHA"]
            or binding["source"] != binding["workflowSource"]
            or re.fullmatch(r"[0-9a-f]{40}", binding["source"]) is None
            or binding["runId"] != os.environ["GITHUB_RUN_ID"]
            or binding["runAttempt"] != os.environ["GITHUB_RUN_ATTEMPT"]
            or binding["tools"]["node"]["command"] != ["node", "--version"]
            or binding["tools"]["node"]["output"] != "v24.20.0"):
        raise ValueError("frontend-source-tool-binding")
    selected = shutil.which("node")
    if selected is None:
        raise ValueError("frontend-node-unavailable")
    node = Path(selected).resolve(strict=True)
    home, temporary = work / "frontend-data-home", work / "frontend-data-tmp"
    receipt = {"schemaVersion": 1, "scope": "four-fixed-frontend-data-suites",
               "source": binding["source"], "workflowSource": binding["workflowSource"],
               "runId": binding["runId"], "runAttempt": binding["runAttempt"],
               "suites": SUITES, "originalReturned": False, "artifactOriginalUnchanged": False,
               "artifactOriginalClosed": False, "scratchEmptyAndRetired": False,
               "nativeUiQualified": False, "testsPassed": False, "passed": False}
    fd = None
    scratch = []
    entered = original_returned = False
    stage = "original-node"
    try:
        fd = os.open(node, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid not in (0, os.getuid())
                or before.st_nlink != 1 or before.st_mode & 0o022 or not before.st_mode & 0o111
                or not 0 < before.st_size <= 256 * 1024 * 1024):
            raise ValueError("frontend-original-node-shape")

        def digest():
            if identity(before) != identity(os.fstat(fd)) or identity(before) != identity(node.lstat()):
                raise ValueError("frontend-original-node-changed")
            value, offset = hashlib.sha256(), 0
            while offset < before.st_size:
                block = os.pread(fd, min(1024 * 1024, before.st_size - offset), offset)
                if not block:
                    raise ValueError("frontend-original-node-short")
                value.update(block)
                offset += len(block)
            if (os.pread(fd, 1, before.st_size) or identity(before) != identity(os.fstat(fd))
                    or identity(before) != identity(node.lstat())):
                raise ValueError("frontend-original-node-changed")
            return value.hexdigest()

        original_hash = digest()
        receipt["node"] = {"path": str(node), "sha256": original_hash, "identity": identity(before)}
        for directory in (home, temporary):
            directory.mkdir(mode=0o700)
            scratch.append((directory, identity(directory.lstat())))
        spec = importlib.util.spec_from_file_location("_mrk_macos_frontend_owner", checkout / "desktop/tools/macos_aqua_qualification.py")
        qualification = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = qualification
        spec.loader.exec_module(qualification)
        owner = qualification.load_owner(checkout)
        argv = ["/usr/bin/sandbox-exec", "-p", NETWORK_POLICY, str(node),
                "--max-old-space-size=192", "--permission", "--allow-fs-read=" + str(checkout),
                "--experimental-strip-types", "--test", "--test-isolation=none", "--test-concurrency=1",
                "--test-reporter=tap", *SUITES]
        stage = "original-test-invocation"
        entered = True
        result = owner.run_owned(argv, cwd=checkout / "desktop",
                                 environ={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home),
                                          "TMPDIR": str(temporary), "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
                                 timeout=60, capture=True, text=False, output_limit=OUTPUT_LIMIT)
        stage = "original-return-contract"
        if not returned_result(result):
            raise ValueError("frontend-original-return-contract")
        original_returned = True
        receipt.update(originalReturned=True, returncode=result.returncode,
                       stdoutSha256=hashlib.sha256(result.stdout).hexdigest(),
                       stderrSha256=hashlib.sha256(result.stderr).hexdigest())
        # These four fixed suites receive only public synthetic source and a
        # clean environment. Keep their bounded failure diagnostics, not host
        # environment/credential dumps. Publication is never cleanup authority.
        stage = "original-test-diagnostics"
        publish(work, "frontend-data-tests.stdout", result.stdout, OUTPUT_LIMIT)
        publish(work, "frontend-data-tests.stderr", result.stderr, OUTPUT_LIMIT)
        stage = "original-node-recheck"
        if digest() != original_hash:
            raise ValueError("frontend-original-node-hash")
        receipt["artifactOriginalUnchanged"] = True
        stage = "original-TAP-result"
        receipt["counts"] = tap_counts(result.stdout)
        if result.returncode != 0 or not counts_pass(receipt["counts"]):
            raise ValueError("frontend-tests-failed")
        receipt["testsPassed"] = True
    except BaseException as error:
        receipt["failure"] = {"stage": stage, "type": type(error).__name__}
        raise
    finally:
        # A failed assertion/publication still permits retiring our proven
        # empty scratch after the original returned. Unknown invocation finality
        # preserves it. Do not derive this decision from a written receipt.
        cleanup_errors = []
        if not entered or original_returned:
            retired = 0
            for directory, original_identity in scratch:
                try:
                    if identity(directory.lstat()) != original_identity:
                        raise ValueError("frontend-scratch-changed")
                    directory.rmdir()  # Empty-only; never recursive deletion.
                    retired += 1
                except (OSError, ValueError) as error:
                    cleanup_errors.append(type(error).__name__)
            receipt["scratchEmptyAndRetired"] = retired == 2
        if cleanup_errors:
            receipt["cleanupErrors"] = cleanup_errors
        if fd is not None:
            original, fd = fd, None
            try:
                os.close(original)
                receipt["artifactOriginalClosed"] = True
            except OSError as error:
                receipt["closeError"] = type(error).__name__
        receipt["passed"] = ("failure" not in receipt and "closeError" not in receipt and not cleanup_errors
                             and all(receipt[key] for key in ("originalReturned", "artifactOriginalUnchanged",
                                                             "artifactOriginalClosed", "scratchEmptyAndRetired", "testsPassed")))
        data = (json.dumps(receipt, sort_keys=True, allow_nan=False) + "\n").encode("ascii")
        publish(work, "frontend-data.receipt.json", data, 16384)
        if ("closeError" in receipt or cleanup_errors) and "failure" not in receipt:
            raise ValueError("frontend-original-cleanup-unconfirmed")


if __name__ == "__main__":
    main()
