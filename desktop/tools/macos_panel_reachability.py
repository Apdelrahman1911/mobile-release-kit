#!/usr/bin/env python3
"""One exploratory AppKit child-tree read, not installed-app qualification.

No process is created at import. Native main uses the unchanged original core
command owner, one tiny compiler invocation and one non-accepting probe.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import threading

REPO = "Apdelrahman1911/mobile-release-kit"
REF = "refs/heads/verify/desktop-macos-panel-probe"
WORKFLOW = ".github/workflows/desktop-macos-panel-probe.yml"
PROBE = "desktop/native/macos-installed-native/tests/panel_reachability_probe.m"
SELF = "desktop/tools/macos_panel_reachability.py"
PINS = {
    "desktop/native/macos-installed-native/src/native.m": "ec69db49d3fe7e175dd62da84935336c0f16e07ad1cf4825b569a2dd0763223d",
    "src/mobile_release/__init__.py": "557bcb0cdcf7f7ef329f04f82cf388c746bb73eba34857b97782a8bcf2e596b2",
    "src/mobile_release/_command_process.py": "075fa6e9838017feb6a1716ab3a75074e3a65dffe8b217613aff7e87c0201f68",
    "src/mobile_release/_lifetime_evidence.py": "d64948f26984ed692030834221f0cfd93b85117da89b4860f8b69a6f7919e1b3",
    "src/mobile_release/_native_process.py": "70c380adde3c2bc06a0985761f0f877355bb56ef09ad506440da93fd4e4ba3b4",
    "src/mobile_release/_store_lane_contract.py": "8726cf9bdb053b3d7f30eb9c8307c18239dc518476b2f895ef1610efa65e040e",
    "src/mobile_release/cancellation.py": "1840232213e877e26c4cebd1434b3b851f9fa4c6961baa26eeaae9fa1442db78",
    "src/mobile_release/errors.py": "26427cedbd05945c1a869af20228f9a04fe1e30d950a2dc246dd0795708a0853",
    "src/mobile_release/owned_process.py": "430a596c5069b7acf248334d1f60fdd12ad8212cf9c2e9dfef717c9ba2179c02",
}
LIMIT = 65536
REASONS = frozenset("none input preparation activation-policy parent-create parent-main-window preparation-deadline panel-reserve panel-arm original-custody read-deadline query-limit original-changed holder-limit retain-return parent-attachment panel-attachment panel-not-visible configuration directory-unavailable directory-type directory-changed nil-element repeated-element element-limit role-type children-unsupported children-nil children-type children-limit depth-limit children-changed ordinary-close ordinary-completion ordinary-release exception ordinary-cleanup".split())


class Refused(Exception):
    pass


def need(value, label):
    if not value:
        raise Refused(label)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def signature(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_file(path, maximum=2 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_size <= maximum, "file-shape")
        chunks = []
        size = 0
        while chunk := os.read(fd, 65536):
            size += len(chunk)
            need(size <= before.st_size, "file-grew")
            chunks.append(chunk)
        need(size == before.st_size and signature(before) == signature(os.fstat(fd))
             == signature(path.lstat()), "file-changed")
        data = b"".join(chunks)
        return data, signature(before)
    finally:
        os.close(fd)


def source_snapshot(root):
    result = {}
    for name in sorted([*PINS, PROBE, SELF, WORKFLOW]):
        data, original = read_file(root / name)
        sha = digest(data)
        need(name not in PINS or sha == PINS[name], "unchanged-component-pin")
        need(original[2] == os.getuid() and original[4] & 0o022 == 0, "source-owner-mode")
        result[name] = {"bytes": len(data), "sha256": sha, "original": original}
    return result


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate-data")
        result[key] = value
    return result


def native_data(content):
    prefix = b"MRK_PANEL_REACHABILITY="
    need(content.startswith(prefix) and content.endswith(b"\n") and content.count(b"\n") == 1
         and len(content) <= 32768, "native-output")
    value = json.loads(content[len(prefix):], object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(Refused("nonfinite-data")))
    booleans = "readOnly semanticOpenIdentity acceptingActionSent prepared bodyEntered bodyReturned preProof postProof custodyKnown timely complete closeReturned completionReturned panelReleased parentReleased poolReturned".split()
    integers = "selectorQueries selectorReturns holders holdersReleased startStatus directoryStatus closeStatus releaseStatus".split()
    need(type(value) is dict and set(value) == {*booleans, *integers, "schemaVersion", "scope", "reason", "rows"}, "native-fields")
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["scope"] == "fresh-normal-parent-not-installed-tauri"
         and all(type(value[k]) is bool for k in booleans)
         and value["readOnly"] and not value["semanticOpenIdentity"] and not value["acceptingActionSent"]
         and all(type(value[k]) is int for k in integers)
         and value["reason"] in REASONS, "native-types")
    need(0 <= value["selectorReturns"] <= value["selectorQueries"] <= 256
         and 0 <= value["holdersReleased"] <= value["holders"] <= 192
         and all(-1 <= value[k] <= 255 for k in integers if k.endswith("Status")), "native-bounds")
    rows = value["rows"]
    need(type(rows) is list and len(rows) <= 32, "native-rows")
    for n, row in enumerate(rows):
        numeric = "ordinal depth viaOrdinal parent window enabled pressCapability pressAllowance children".split()
        need(type(row) is dict and set(row) == {*numeric, "role", "rowRead"}
             and all(type(row[k]) is int for k in numeric) and type(row["rowRead"]) is bool
             and row["role"] in ("unobserved", "unsupported", "nil", "other", "button", "sheet", "group", "window"), "native-row-types")
        need(row["ordinal"] == n and 0 <= row["depth"] <= 4
             and (row["viaOrdinal"] == 32 if n == 0 else 0 <= row["viaOrdinal"] < n)
             and (row["depth"] == 0 if n == 0 else row["depth"] == rows[row["viaOrdinal"]]["depth"] + 1)
             and all(0 <= row[k] <= 6 for k in ("parent", "window"))
             and all(0 <= row[k] <= 3 for k in ("enabled", "pressCapability", "pressAllowance"))
             and -3 <= row["children"] <= 18, "native-row-bounds")
    return value


def write_json(path, value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    need(len(data) <= 262144, "report-bound")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        offset = 0
        while offset < len(data):
            count = os.write(fd, data[offset:])
            need(count > 0, "report-write")
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    root = Path(__file__).absolute().parents[2]
    report = {"schemaVersion": 1, "scope": "read-only-exploratory-panel-reachability",
              "nativeQualified": False, "installedTauriQualified": False, "distributionQualified": False,
              "originalNativeCallReturned": False, "nativeReturncode": None, "native": None,
              "sourcePrePostMatched": False, "commands": [], "stage": "admission", "error": None,
              "limits": {"readSeconds": 2, "custodySeconds": 45, "processSeconds": 60,
                         "elements": 32, "childrenPerNode": 16, "depth": 4, "selectorQueries": 256},
              "cleanup": {"binaryRemoved": False, "privateDirectoriesRemoved": False,
                          "unknownStateRetained": False, "error": None}}
    work = owner = before = binary_pin = None
    inflight = False
    success = False
    try:
        need(len(sys.argv) == 1 and sys.platform == "darwin" and platform.machine() == "arm64"
             and platform.mac_ver()[0].split(".")[0] == "26" and threading.current_thread() is threading.main_thread(), "native-host")
        uid, gid = os.getuid(), os.getgid()
        need(uid > 0 and uid == os.geteuid() and gid == os.getegid(), "native-user")
        sha, run, attempt = (os.environ.get(k, "") for k in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
        need(re.fullmatch(r"[0-9a-f]{40}", sha) and all(re.fullmatch(r"[1-9][0-9]{0,19}", x) for x in (run, attempt)), "source-run")
        expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
                    "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": REPO, "GITHUB_REF": REF,
                    "GITHUB_WORKFLOW_REF": f"{REPO}/{WORKFLOW}@{REF}", "GITHUB_WORKFLOW_SHA": sha,
                    "GITHUB_WORKSPACE": str(root), "DEVELOPER_DIR": "/Library/Developer/CommandLineTools"}
        need(all(os.environ.get(k) == v for k, v in expected.items()), "hosted-route")
        head, _ = read_file(root / ".git" / "HEAD", 41)
        need(head == sha.encode() + b"\n", "detached-source")
        before = source_snapshot(root)
        python_body, _ = read_file(Path(sys.executable).resolve(strict=True), 4 * 1024 * 1024)
        report.update(sourceCommit=sha, runId=run, runAttempt=attempt, platform=platform.mac_ver()[0], architecture="arm64",
                      pythonVersion=sys.version, pythonExecutableSha256=digest(python_body),
                      sourceFiles={k: {"bytes": v["bytes"], "sha256": v["sha256"]} for k, v in before.items()})
        need(not any(k == "mobile_release" or k.startswith("mobile_release.") for k in sys.modules), "owner-import")
        sys.path.insert(0, str(root / "src"))
        try:
            from mobile_release import owned_process as owner
        finally:
            sys.path.pop(0)
        need(Path(owner.__file__).absolute() == root / "src/mobile_release/owned_process.py", "original-owner")
        os.umask(0o077)
        work = Path("/private/tmp") / f"mrk-macos-panel-probe-{sha}-{run}-{attempt}"
        work.mkdir(mode=0o700)  # Exact fresh path; collision is never repaired.
        original_work = signature(work.lstat())[:5]
        originals = {}
        for name in ("home", "tmp", "project", "evidence"):
            (work / name).mkdir(mode=0o700)
            originals[name] = signature((work / name).lstat())[:5]
        username = pwd.getpwuid(uid).pw_name
        need(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", username), "username")
        environment = {"HOME": str(work / "home"), "TMPDIR": str(work / "tmp") + "/",
                       "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TZ": "UTC",
                       "USER": username, "LOGNAME": username, "__CF_USER_TEXT_ENCODING": f"0x{uid:X}:0:0",
                       "DEVELOPER_DIR": "/Library/Developer/CommandLineTools"}

        def call(role, argv, timeout):
            nonlocal inflight
            report["stage"] = role
            inflight = True
            result = owner.run_owned(argv, environ=environment, cwd=work, timeout=timeout,
                                     capture=True, text=False, output_limit=LIMIT)
            need(type(result) is subprocess.CompletedProcess and type(result.args) is list
                 and result.args == argv and type(result.returncode) is int
                 and type(result.stdout) is bytes and type(result.stderr) is bytes
                 and len(result.stdout) + len(result.stderr) <= LIMIT, "owner-return-contract")
            inflight = False
            report["commands"].append({"role": role, "originalCallReturned": True, "returncode": result.returncode,
                                       "stdoutBytes": len(result.stdout), "stdoutSha256": digest(result.stdout),
                                       "stderrBytes": len(result.stderr), "stderrSha256": digest(result.stderr)})
            return result

        version = call("compiler-version", ["/usr/bin/xcrun", "--sdk", "macosx", "clang", "--version"], 15)
        need(version.returncode == 0 and not version.stderr and len(version.stdout) <= 4096, "compiler-version")
        first = version.stdout.decode("ascii", "strict").splitlines()[0]
        need(first.startswith("Apple clang version ") and len(first) <= 256, "compiler-version")
        report["compilerVersion"] = first
        sdk = call("sdk-version", ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version"], 15)
        need(sdk.returncode == 0 and not sdk.stderr and re.fullmatch(rb"26(?:\.[0-9]+){1,2}\n", sdk.stdout), "sdk-version")
        report["sdkVersion"] = sdk.stdout.decode().strip()
        binary = work / "panel-probe"
        arguments = ["/usr/bin/xcrun", "--sdk", "macosx", "clang", "-O0", "-fno-objc-arc", "-fblocks",
                     "-mmacosx-version-min=26.0", "-DMRK_INSTALLED_OBSERVATION", "-Wall", "-Wextra",
                     "-framework", "AppKit", "-framework", "Foundation", "-framework", "ApplicationServices",
                     str(root / PROBE), "-o", str(binary)]
        compiled = call("compile", arguments, 60)
        if compiled.returncode != 0:
            # This is public synthetic source/tool output, not a native UI or user transcript.
            errors = []
            for line in compiled.stderr.decode("utf-8", "replace").splitlines():
                if "error:" in line:
                    errors.append(line.split("error:", 1)[1][:400])
                    if len(errors) == 8:
                        break
            report["compilerErrors"] = errors
        need(compiled.returncode == 0, "compile")
        binary_body, binary_pin = read_file(binary, 4 * 1024 * 1024)
        report["compiledBinary"] = {"bytes": len(binary_body), "sha256": digest(binary_body)}
        need(source_snapshot(root) == before, "source-before-native")
        observed = call("native-read", [str(binary), str(work / "project")], 60)
        report["originalNativeCallReturned"] = True
        report["nativeReturncode"] = observed.returncode
        report["native"] = native_data(observed.stdout)
        native = report["native"]
        success = observed.returncode == 0 and all(native[k] for k in
            ("prepared", "bodyEntered", "bodyReturned", "preProof", "postProof", "custodyKnown", "timely", "complete",
             "closeReturned", "completionReturned", "panelReleased", "parentReleased", "poolReturned"))
        success = success and native["reason"] == "none" and native["selectorQueries"] == native["selectorReturns"]
        success = success and native["holders"] == native["holdersReleased"] and bool(native["rows"]) and all(r["rowRead"] for r in native["rows"])
        need(source_snapshot(root) == before, "source-after-native")
        report["sourcePrePostMatched"] = True
        report["stage"] = "returned"
    except BaseException as error:
        report["error"] = str(error) if type(error) is Refused else "interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "adapter-or-owner-error"
        if owner is not None and isinstance(error, (owner.ProcessError, owner.ProcessInterrupted)):
            report["ownerFailure"] = {"dispatched": error.dispatched, "contained": error.contained,
                                       "cleanupComplete": getattr(error, "cleanup_complete", None)}
        success = False
    # Only the original returned command clears inflight; exception flags alone
    # never authorize fixture readback, another child or disposal.
    if work is not None and work.exists() and "original_work" in locals():
        try:
            need(signature(work.lstat())[:5] == original_work, "work-original")
            if inflight:
                report["cleanup"]["unknownStateRetained"] = True
            else:
                if binary_pin is not None:
                    current, identity = read_file(work / "panel-probe", 4 * 1024 * 1024)
                    need(identity == binary_pin and digest(current) == report["compiledBinary"]["sha256"], "binary-original")
                    (work / "panel-probe").unlink()
                    report["cleanup"]["binaryRemoved"] = True
                elif any(c["role"] == "compile" for c in report["commands"]) and (work / "panel-probe").exists():
                    # A returned failed compiler may leave a disposable partial
                    # output in its originally empty, private output directory.
                    _, identity = read_file(work / "panel-probe", 4 * 1024 * 1024)
                    need(signature((work / "panel-probe").lstat()) == identity, "partial-binary-original")
                    (work / "panel-probe").unlink()
                    report["cleanup"]["binaryRemoved"] = True
                if (report.get("native") or {}).get("poolReturned"):
                    need(shutil.rmtree.avoids_symlink_attacks, "ordinary-tree-removal")
                    fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    try:
                        need(signature(os.fstat(fd))[:5] == original_work, "work-open-original")
                        for name in ("project", "home", "tmp"):
                            need(signature(os.stat(name, dir_fd=fd, follow_symlinks=False))[:5] == originals[name], "private-directory-original")
                            shutil.rmtree(name, dir_fd=fd)
                        need(os.listdir(fd) == ["evidence"], "private-postcondition")
                    finally:
                        os.close(fd)
                    report["cleanup"]["privateDirectoriesRemoved"] = True
                else:
                    report["cleanup"]["unknownStateRetained"] = True
        except BaseException:
            report["cleanup"]["error"] = "original-cleanup-refused"
            success = False
        report["diagnosticComplete"] = success
        try:
            write_json(work / "evidence" / "result.json", report)
        except BaseException:
            return 1
    else:
        # No native output or private source/path/error text is printed.
        print(json.dumps({"schemaVersion": 1, "diagnosticComplete": False, "stage": report["stage"], "error": report["error"]}, sort_keys=True))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
