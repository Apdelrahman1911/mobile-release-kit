#!/usr/bin/env python3
"""Fixed hosted startup-policy checks of the real release helper; never a runner UI.

Only the native main loads the existing owner. Imports/tests are DATA-only.
No helper request, credential, environment value or child output is exported.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

REPOSITORY = "Apdelrahman1911/mobile-release-kit"
REF = "refs/heads/verify/desktop-macos-vault-startup"
WORKFLOW = REPOSITORY + "/.github/workflows/desktop-macos-vault-startup.yml@" + REF
WORKSPACE = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
TEMP = Path("/Users/runner/work/_temp")
HELPER = "vault-helper-target/aarch64-apple-darwin/release/mrk-vault-keychain"
TIMEOUT = 10
OUTPUT_LIMIT = 4096
FILE_LIMIT = 32 * 1024 * 1024
CATEGORIES = {64: "bad-argc", 65: "cf-encoding-refused", 66: "other-nonempty-environment", 1: "no-startup-refusal"}


class Refused(Exception):
    """Only closed adapter labels, never native/OS exception strings."""


def need(condition, label):
    if not condition:
        raise Refused(label)


@dataclass(frozen=True)
class Case:
    name: str
    extra: tuple[str, ...]
    environment: dict[str, str]
    expected: tuple[int, ...]


def cases(uid):
    need(type(uid) is int and 0 < uid <= 0xFFFFFFFF, "account")
    # Deliberately synthetic values, never inherited or published. The malformed
    # case keeps the UID correct so the historical framework getter need not
    # replace a foreign-UID preference before main. Native results, not that
    # history, establish today's compatibility; no case authenticates a caller.
    return (
        Case("bad-argc", ("mrk-startup-fixture",), {}, (64,)),
        Case("canonical-cf", (), {"__CF_USER_TEXT_ENCODING": f"0x{uid:X}:0:0"}, (1,)),
        Case("malformed-cf", (), {"__CF_USER_TEXT_ENCODING": f"0x{uid:X}:not-an-encoding"}, (65,)),
        Case("other-name", (), {"MRK_STARTUP_DIAGNOSTIC": "synthetic"}, (66,)),
        Case("empty-parent-env", (), {}, (1,)),
    )


@dataclass
class Run:
    rows: list[dict] = field(default_factory=list)
    inflight: bool = False
    last_returned: bool = False
    failed: bool = False
    case: str | None = None


def run_cases(run_owned, helper, cwd, uid, check_originals, state):
    """One invocation seam; DATA tests supply a non-executing callable."""
    for case in cases(uid):
        check_originals()
        argv = [str(helper), *case.extra]
        state.case, state.inflight, state.last_returned = case.name, True, False
        result = run_owned(argv, environ=dict(case.environment), cwd=cwd,
                           timeout=TIMEOUT, capture=True, text=False, output_limit=OUTPUT_LIMIT)
        state.last_returned = True
        # Return alone is not a usable result/finality receipt. No readback or
        # later case follows malformed data, output, or a native owner error.
        need(type(result) is subprocess.CompletedProcess and type(result.args) is list
             and all(type(arg) is str for arg in result.args) and result.args == argv
             and type(result.returncode) is int and 0 <= result.returncode <= 255
             and type(result.stdout) is bytes and type(result.stderr) is bytes
             and len(result.stdout) + len(result.stderr) <= OUTPUT_LIMIT, "owner-result")
        need(not result.stdout and not result.stderr, "unexpected-output")
        # Success is outside every fixed refusal/EOF case. Do not infer
        # continuation, postreadback or scratch cleanup from that result.
        need(result.returncode != 0, "unexpected-success")
        state.inflight = False
        check_originals()
        matched = result.returncode in case.expected
        state.failed |= not matched
        state.rows.append({"case": case.name, "exitCode": result.returncode,
                           "category": CATEGORIES.get(result.returncode, "unexpected-code"),
                           "matched": matched, "outputEmpty": True, "originalCallSettled": True})
    return not state.failed


def signature(info):
    # Full integers stay in Python; no JS conversion or truncated custody key.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class Originals:
    """Task-owned descriptor custody only; run_owned owns every process."""

    def __init__(self, root, uid):
        self.root, self.uid = root, uid
        self.held = []
        self.binary = self.cwd = None
        self.digest = None
        self.bytes = None

    def directory(self, path, parent=None, name=None):
        fd = os.open(path if parent is None else name,
                     os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        self.held.append((fd, parent, path if parent is None else name, None))
        info = os.fstat(fd)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == self.uid
             and not info.st_mode & 0o022, "directory-custody")
        original = signature(info)[:5]
        self.held[-1] = (fd, parent, path if parent is None else name, original)
        return fd

    def open(self, origin):
        root = self.directory(self.root)
        need(list(signature(os.fstat(root))[:5]) == origin, "work-origin")
        self.cwd = self.directory(None, root, "case-cwd")
        parent = root
        for name in HELPER.split("/")[:-1]:
            parent = self.directory(None, parent, name)
        name = HELPER.rsplit("/", 1)[1]
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        self.held.append((fd, parent, name, None))
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == self.uid and info.st_nlink == 1
             and info.st_mode & 0o100 and not info.st_mode & 0o022
             and 0 < info.st_size <= FILE_LIMIT, "helper-custody")
        original = signature(info)
        self.held[-1] = (fd, parent, name, original)
        self.binary = fd
        self.bytes = info.st_size
        self.digest = self.hash_helper()
        self.check()

    def hash_helper(self):
        os.lseek(self.binary, 0, os.SEEK_SET)
        digest, used = hashlib.sha256(), 0
        while block := os.read(self.binary, 65536):
            used += len(block)
            need(used <= FILE_LIMIT, "helper-size")
            digest.update(block)
        need(used == os.fstat(self.binary).st_size, "helper-size")
        return digest.hexdigest()

    def check(self):
        for fd, parent, name, original in self.held:
            need(original is not None, "original-unbound")
            held = signature(os.fstat(fd))
            named = signature(os.stat(name, dir_fd=parent, follow_symlinks=False))
            need(held[:len(original)] == original and named[:len(original)] == original, "original-changed")
        need(os.listdir(self.cwd) == [], "cwd-roster")
        need(self.hash_helper() == self.digest, "helper-changed")

    def close(self):
        failed = False
        for fd, _, _, _ in reversed(self.held):
            try:
                os.close(fd)
            except OSError:
                failed = True  # Other distinct original descriptors still close.
        self.held.clear()
        need(not failed, "original-close")


def read_json(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1 and 0 < before.st_size <= limit, "binding-file")
        data = bytearray()
        while block := os.read(fd, min(65536, limit + 1 - len(data))):
            data.extend(block)
            need(len(data) <= limit, "binding-size")
        need(len(data) == before.st_size and signature(os.fstat(fd)) == signature(before)
             and signature(os.stat(path, follow_symlinks=False)) == signature(before), "binding-changed")
        return json.loads(data)
    finally:
        os.close(fd)


def admit(environ, checkout):
    need(sys.platform == "darwin" and os.uname().machine == "arm64" and os.getuid() != 0
         and os.getuid() == os.geteuid() and os.getgid() == os.getegid(), "platform")
    need(checkout == WORKSPACE and Path.cwd() == checkout and len(sys.argv) == 1, "entry-route")
    expected = {"RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
                "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_EVENT_NAME": "push", "GITHUB_REF": REF,
                "GITHUB_WORKFLOW_REF": WORKFLOW, "GITHUB_JOB": "startup", "RUNNER_TEMP": str(TEMP)}
    need(all(environ.get(key) == value for key, value in expected.items()), "hosted-route")
    source = environ.get("GITHUB_SHA", "")
    need(re.fullmatch(r"[0-9a-f]{40}", source) is not None
         and environ.get("GITHUB_WORKFLOW_SHA") == source, "source-route")
    need(all(re.fullmatch(r"[1-9][0-9]{0,19}", environ.get(key, "")) is not None
             for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")), "attempt-route")
    work = Path(environ.get("MRK_MACOS_WORK", ""))
    need(work.parent == TEMP and re.fullmatch(r"mrk-macos-vault-startup\.[A-Za-z0-9]{8}", work.name) is not None,
         "work-route")
    binding = read_json(work / "source-binding.json", 4096)
    inventory = read_json(work / "source-inventory.json", 2 * 1024 * 1024)
    need(binding["source"] == source == inventory["source"] and binding["tree"] == inventory["tree"]
         and binding["workflowSource"] == source and binding["runId"] == environ["GITHUB_RUN_ID"]
         and binding["runAttempt"] == environ["GITHUB_RUN_ATTEMPT"]
         and re.fullmatch(r"[0-9a-f]{40}", binding["tree"]) is not None
         and type(binding["workDirectory"]) is list and len(binding["workDirectory"]) == 5
         and all(type(value) is int and value >= 0 for value in binding["workDirectory"]), "source-binding")
    return work, binding, inventory


def load_owner(checkout, inventory):
    # Reuse the existing pinned owner loader, not a parallel command controller.
    relative = "desktop/tools/macos_aqua_qualification.py"
    rows = [row for row in inventory["files"] if row["path"] == relative]
    need(len(rows) == 1, "owner-loader-binding")
    path = checkout / relative
    need(hashlib.sha256(path.read_bytes()).hexdigest() == rows[0]["sha256"], "owner-loader-source")
    spec = importlib.util.spec_from_file_location("mrk_startup_aqua_owner_source", path)
    need(spec is not None and spec.loader is not None and spec.name not in sys.modules, "owner-loader")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.load_owner(checkout)


def lifetime_facts(error, owner):
    facts, pending, seen = [], [error], set()
    while pending and len(seen) < 8:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if owner is not None and isinstance(current, (owner.ProcessError, owner.ProcessInterrupted)):
            facts.append({target: value if type(value) is bool else None
                          for name, target in (("dispatched", "dispatched"), ("contained", "contained"),
                                               ("cleanup_complete", "cleanupComplete"))
                          for value in (getattr(current, name, None),)})
        pending.extend((current.__cause__, current.__context__))
    return facts


def main():
    state, originals, owner, binding, error = Run(), None, None, None, None
    closed = False
    try:
        checkout = Path(__file__).absolute().parents[2]
        work, binding, inventory = admit(os.environ, checkout)
        originals = Originals(work, os.getuid())
        originals.open(binding["workDirectory"])
        owner = load_owner(checkout, inventory)
        run_cases(owner.run_owned, work / HELPER, work / "case-cwd", os.getuid(), originals.check, state)
    except BaseException as caught:
        error = caught
    if originals is not None and not state.inflight:
        try:
            originals.close()
            closed = True
        except BaseException as caught:
            if error is None:
                error = caught
    label = str(error) if type(error) is Refused else "adapter-or-owner-error" if error else None
    if label is not None and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", label) is None:
        label = "adapter-error"
    passed = error is None and not state.failed and closed and len(state.rows) == 5
    # A settled mismatch is still failed, but it can safely retire owned build
    # scratch. Any exception/unknown keeps those originals for host teardown.
    safe_cleanup = error is None and closed and not state.inflight and len(state.rows) == 5
    value = {"schemaVersion": 1, "type": "macos-vault-helper-startup", "status": "passed" if passed else "failed",
             "workflow": WORKFLOW, "platform": "macos-26-arm64", "toolchain": "1.98.1",
             "profile": "release-aarch64-apple-darwin",
             "source": binding["source"] if binding else None, "tree": binding["tree"] if binding else None,
             "workflowSource": binding["workflowSource"] if binding else None,
             "runId": binding["runId"] if binding else None, "runAttempt": binding["runAttempt"] if binding else None,
             "helperSha256": originals.digest if originals else None, "helperBytes": originals.bytes if originals else None,
             "cases": state.rows,
             "failedAtCase": state.case if error else None, "reason": label,
             "originalCallReturned": state.last_returned, "invocationFinality": "unknown" if state.inflight else "no-pending-invocation",
             "typedLifetimeFacts": lifetime_facts(error, owner), "originalDescriptorsClosed": closed,
             "cleanupAuthorized": safe_cleanup, "rawOutputIncluded": False, "environmentValuesIncluded": False,
             "startupDiagnosticOnly": True, "installedCallerQualified": False, "keychainQualified": False,
             "distributionQualified": False}
    try:
        data = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")
        need(len(data) <= 16384, "report-size")
        if os.write(1, data) != len(data):
            return 1
    except BaseException:
        return 1
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
