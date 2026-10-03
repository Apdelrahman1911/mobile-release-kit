#!/usr/bin/env python3
"""One fixed hosted M2 entry experiment; no production maintenance or Store work.

Imports are DATA-only. Native main reuses the reviewed Aqua owner loader and
the existing original command owner. NSWorkspace app exit status remains unknown.
"""
from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import threading

REPO = "Apdelrahman1911/mobile-release-kit"
REF = "refs/heads/verify/desktop-macos-m2-entry"
WORKFLOW = ".github/workflows/desktop-macos-m2-entry.yml"
NATIVE = "desktop/native/macos-m2-entry"
SELF = "desktop/tools/macos_m2_entry_feasibility.py"
LOADER = "desktop/tools/macos_aqua_qualification.py"
LOADER_SHA = "3841106e181c919a4657f4bbbe33aa679a8367f3d7d2b80abce693d602d20053"
TESTS = "tests/desktop/test_macos_m2_entry_feasibility.py"
SOURCES = (WORKFLOW, SELF, LOADER, TESTS, *(NATIVE + "/" + name for name in
           ("fixture.h", "entry.c", "payload.m", "observe.m", "README.md")))
LIMIT = 65536
PAYLOAD_FLAGS = frozenset("entryPidPreserved originalAccount gateIdentity gateInheritedWithoutCLOEXEC gateMarkedCLOEXEC exclusiveWouldBlock executableIsPayload mainBundleIsPayload mainBundleIDIsPayload runningObjectExists runningExecutableIsPayload runningExecutableIsEntry runningBundleIsPayload runningBundleIsEntry runningIDIsPayload runningIDIsEntry didFinishLaunching windowVisible appActive".split())
PAYLOAD_IDENTITY_PAIRS = (("runningExecutableIsEntry", "runningExecutableIsPayload"),
                          ("runningBundleIsEntry", "runningBundleIsPayload"), ("runningIDIsEntry", "runningIDIsPayload"))
REFERENCE_IDENTITY_PAIRS = (("referenceBundleIsEntry", "referenceBundleIsPayload"),
                            ("referenceExecutableIsEntry", "referenceExecutableIsPayload"))
REQUIRED_PAYLOAD = PAYLOAD_FLAGS - {flag for pair in PAYLOAD_IDENTITY_PAIRS for flag in pair}
OBSERVER_FLAGS = frozenset("launchRequested launchReferenceReturned launchErrorReported referencePIDMatchesPayload referenceBundleIsEntry referenceBundleIsPayload referenceExecutableIsEntry referenceExecutableIsPayload exclusiveBlockedWhilePayloadAlive normalQuitRequestSent terminationObserved exclusiveAvailableAfterTermination rootCloseReturned timely observationComplete workDeadlineFailed".split())
COUNTS = frozenset(("completionCount", "completionBodyDoneCount", "completionHandoffCount"))
FAILURES = frozenset("none launch-completion payload-record payload-terminated-before-observation original-reference-or-shared-bridge observation-deadline quit-record normal-quit-or-last-holder native-exception cleanup-native-exception root-close final-deadline".split())


class Refused(Exception):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_file(path, maximum=512 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
             "original-file-shape")
        parts, used = [], 0
        while chunk := os.read(fd, 65536):
            used += len(chunk)
            need(used <= before.st_size, "original-file-grew")
            parts.append(chunk)
        need(used == before.st_size and signature(before) == signature(os.fstat(fd))
             == signature(path.lstat()), "original-file-changed")
        return b"".join(parts), signature(before)
    finally:
        os.close(fd)  # One consuming close only.


def pairs(rows):
    result = {}
    for key, value in rows:
        need(key not in result, "duplicate-data")
        result[key] = value
    return result


def document(data):
    need(type(data) is bytes and 0 < len(data) <= 32768, "data-bound")
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refused("nonfinite-data")))
    except (ValueError, UnicodeError) as error:
        raise Refused("invalid-json-data") from error


def record(value, source, flags, extra=()):
    need(type(value) is dict and set(value) == {"schemaVersion", "source", *flags, *extra}
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["source"] == source and all(type(value[k]) is bool for k in flags), "record-contract")


def native_data(data, source):
    prefix = b"MRK_M2_ENTRY="
    need(type(data) is bytes and data.startswith(prefix) and data.endswith(b"\n")
         and data.count(b"\n") == 1, "native-output")
    value = document(data[len(prefix):])
    record(value, source, OBSERVER_FLAGS, (*COUNTS, "scope", "payloadStart", "payloadQuit",
                                         "originalAppExitStatus", "allWorkerFinality", "firstFailure"))
    need(value["scope"] == "synthetic-nsworkspace-entry-feasibility"
         and all(type(value[k]) is int and 0 <= value[k] <= 2 for k in COUNTS)
         and value["originalAppExitStatus"] is None
         and value["allWorkerFinality"] == "not-established-by-NSRunningApplication"
         and type(value["firstFailure"]) is str and value["firstFailure"] in FAILURES, "native-claims")
    if value["payloadStart"] is not None:
        row = value["payloadStart"]
        record(row, source, PAYLOAD_FLAGS, ("scope", "processIdentifier"))
        need(row["scope"] == "synthetic-appkit-payload-not-tauri"
             and type(row["processIdentifier"]) is int and 1 < row["processIdentifier"] < 2**31,
             "payload-identity-data")
        need(all(not (row[a] and row[b]) for a, b in PAYLOAD_IDENTITY_PAIRS), "payload-exclusive-identities")
    if value["payloadQuit"] is not None:
        record(value["payloadQuit"], source, ("normalQuitDelegateObserved", "gateStillHeldAtWillTerminate"))
    need(all(not (value[a] and value[b]) for a, b in REFERENCE_IDENTITY_PAIRS), "reference-exclusive-identities")
    return value


def supported_observation(value):
    """A narrow boundary observation; never a product/clean-exit qualification."""
    required = OBSERVER_FLAGS - {"launchErrorReported", "workDeadlineFailed", *(flag for pair in REFERENCE_IDENTITY_PAIRS for flag in pair)}
    return (value["firstFailure"] == "none" and not value["launchErrorReported"] and not value["workDeadlineFailed"]
            and all(value[k] for k in required) and all(value[k] == 1 for k in COUNTS)
            and value["payloadStart"] is not None and value["payloadQuit"] is not None
            and all(value["payloadStart"][k] for k in REQUIRED_PAYLOAD)
            and all(value[a] != value[b] for a, b in REFERENCE_IDENTITY_PAIRS)
            and all(value["payloadStart"][a] != value["payloadStart"][b] for a, b in PAYLOAD_IDENTITY_PAIRS)
            and value["payloadQuit"]["normalQuitDelegateObserved"]
            and value["payloadQuit"]["gateStillHeldAtWillTerminate"])


def snapshot(root, pins):
    result = {}
    for relative in sorted(set(SOURCES) | set(pins)):
        body, original = read_file(root / relative)
        need(original[3] == os.getuid() and not original[2] & 0o022, "source-owner-mode")
        sha = digest(body)
        need(relative not in pins or sha == pins[relative], "source-pin")
        result[relative] = {"bytes": len(body), "sha256": sha, "original": original}
    return result


def write_new(path, body, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        offset = 0
        while offset < len(body):
            count = os.write(fd, body[offset:])
            need(count > 0, "output-write")
            offset += count
        os.fchmod(fd, mode)  # This original was just created exclusively, never repair.
        os.fsync(fd)
    finally:
        os.close(fd)


def tree(root):
    result, total = {}, 0
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            info = (Path(folder) / name).lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022,
                 "generated-directory")
        for name in files:
            path = Path(folder) / name
            body, original = read_file(path, 8 * 1024 * 1024)
            total += len(body)
            need(len(result) < 128 and total <= 32 * 1024 * 1024 and original[3] == os.getuid(),
                 "generated-tree-bound")
            result[str(path.relative_to(root))] = {"bytes": len(body), "sha256": digest(body), "original": original}
    return result


def main():
    root = Path(__file__).absolute().parents[2]
    report = {"schemaVersion": 1, "scope": "m2-entry-feasibility-only", "feasibilityObserved": False,
              "installedProductQualified": False, "tauriQualified": False, "credentialQualified": False,
              "maintenanceAvailable": False, "commands": [], "native": None,
              "stage": "admission", "error": None, "sourcePrePostMatched": False,
              "cleanup": {"disposableRemoved": False, "unknownStateRetained": False,
                          "applicationImagesAndTempRetained": False, "error": None}}
    owner = work = before = bundle_pins = None
    inflight = False
    last_returned = False
    success = False
    try:
        need(len(sys.argv) == 1 and sys.platform == "darwin" and platform.machine() == "arm64"
             and platform.mac_ver()[0].split(".")[0] == "26" and threading.current_thread() is threading.main_thread(),
             "native-host")
        uid, gid = os.getuid(), os.getgid()
        account = pwd.getpwuid(uid)
        need(uid > 0 and uid == os.geteuid() and gid == os.getegid() and account.pw_uid == uid
             and account.pw_gid == gid and account.pw_name == "runner" and account.pw_dir == "/Users/runner", "account")
        sha, run, attempt = (os.environ.get(k, "") for k in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
        need(re.fullmatch(r"[0-9a-f]{40}", sha) and all(re.fullmatch(r"[1-9][0-9]{0,19}", v) for v in (run, attempt)), "source-run")
        expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
                    "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": REPO, "GITHUB_REF": REF,
                    "GITHUB_WORKFLOW_REF": f"{REPO}/{WORKFLOW}@{REF}", "GITHUB_WORKFLOW_SHA": sha,
                    "GITHUB_WORKSPACE": str(root), "DEVELOPER_DIR": "/Library/Developer/CommandLineTools"}
        need(all(os.environ.get(k) == v for k, v in expected.items()), "hosted-route")
        need(read_file(root / ".git/HEAD", 41)[0] == sha.encode() + b"\n", "detached-source")
        need(digest(read_file(root / LOADER)[0]) == LOADER_SHA, "owner-loader-pin")
        spec = importlib.util.spec_from_file_location("mrk_m2_entry_original_owner_loader", root / LOADER)
        need(spec is not None and spec.loader is not None and spec.name not in sys.modules, "owner-loader")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        pins = {"src/mobile_release/" + name: expected for name, expected in module.OWNER_PINS.items()}
        pins[LOADER] = LOADER_SHA
        before = snapshot(root, pins)
        owner = module.load_owner(root)
        report.update(sourceCommit=sha, runId=run, runAttempt=attempt, platform=platform.mac_ver()[0],
                      architecture="arm64", pythonVersion=sys.version,
                      sourceFiles={k: {"bytes": v["bytes"], "sha256": v["sha256"]} for k, v in before.items()})
        os.umask(0o077)
        work = Path("/private/tmp") / f"mrk-macos-m2-entry-{sha}-{run}-{attempt}"
        work.mkdir(mode=0o700)
        work_original = signature(work.lstat())[:5]
        for name in ("build", "tmp", "app-tmp", "evidence"):
            (work / name).mkdir(mode=0o700)
        write_new(work / "maintenance-use.lock", b"", 0o444)
        gate_original = signature((work / "maintenance-use.lock").lstat())
        suffix = f"{sha}-{run}-{attempt}"
        entry_id, payload_id = "dev.mobile-release-kit.m2-entry." + suffix, "dev.mobile-release-kit.m2-payload." + suffix
        header = (f"#define MRK_ROOT {json.dumps(str(work))}\n#define MRK_SOURCE {json.dumps(sha)}\n"
                  f"#define MRK_UID {uid}U\n#define MRK_GID {gid}U\n"
                  f"#define MRK_GATE_DEVICE {gate_original[0]}ULL\n#define MRK_GATE_INODE {gate_original[1]}ULL\n"
                  f"#define MRK_ENTRY_ID {json.dumps(entry_id)}\n#define MRK_PAYLOAD_ID {json.dumps(payload_id)}\n").encode()
        write_new(work / "build/fixture_config.h", header, 0o400)
        report["generatedHeader"] = {"bytes": len(header), "sha256": digest(header)}
        environment = {"HOME": "/Users/runner", "TMPDIR": str(work / "tmp") + "/", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                       "USER": "runner", "LOGNAME": "runner", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TZ": "UTC",
                       "__CF_USER_TEXT_ENCODING": f"0x{uid:X}:0:0", "DEVELOPER_DIR": "/Library/Developer/CommandLineTools"}

        def check_sources():
            need(snapshot(root, pins) == before, "source-changed")
            need(signature((work / "maintenance-use.lock").lstat()) == gate_original, "gate-changed")

        def call(role, argv, timeout):
            nonlocal inflight, last_returned
            check_sources()
            report["stage"] = role
            inflight, last_returned = True, False
            result = owner.run_owned(argv, environ=environment, cwd=work, timeout=timeout,
                                     capture=True, text=False, output_limit=LIMIT)
            last_returned = True
            need(type(result) is subprocess.CompletedProcess and type(result.args) is list and result.args == argv
                 and type(result.returncode) is int and 0 <= result.returncode <= 255
                 and type(result.stdout) is bytes and type(result.stderr) is bytes
                 and len(result.stdout) + len(result.stderr) <= LIMIT, "owner-return-contract")
            inflight = False
            report["commands"].append({"role": role, "originalCallReturned": True, "returncode": result.returncode,
                                       "stdoutBytes": len(result.stdout), "stdoutSha256": digest(result.stdout),
                                       "stderrBytes": len(result.stderr), "stderrSha256": digest(result.stderr)})
            check_sources()
            return result

        def zero(role, argv, timeout=30):
            result = call(role, argv, timeout)
            if result.returncode != 0 and "compile" in role:
                report["compilerErrors"] = [line.split("error:", 1)[1][:400]
                    for line in result.stderr.decode("utf-8", "replace").splitlines() if "error:" in line][:8]
            need(result.returncode == 0, role + "-status")
            return result

        def bundle(name, executable, identifier):
            target = work / name
            for path in (target, target / "Contents", target / "Contents/MacOS"):
                path.mkdir(mode=0o700)
            info = {"CFBundleExecutable": executable, "CFBundleIdentifier": identifier,
                    "CFBundleName": name.removesuffix(".app"), "CFBundlePackageType": "APPL",
                    "CFBundleVersion": "1", "CFBundleShortVersionString": "1.0", "LSMinimumSystemVersion": "26.0",
                    "LSMultipleInstancesProhibited": False, "NSHighResolutionCapable": True}
            write_new(target / "Contents/Info.plist", plistlib.dumps(info, sort_keys=True), 0o444)
            return target

        compiler = ["/usr/bin/xcrun", "--sdk", "macosx", "clang"]
        version = zero("compiler-version", compiler + ["--version"], 15)
        need(not version.stderr and version.stdout.startswith(b"Apple clang version ") and len(version.stdout) <= 4096, "compiler-version")
        report["compilerVersion"] = version.stdout.decode("ascii").splitlines()[0]
        sdk = zero("sdk-version", ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version"], 15)
        need(not sdk.stderr and re.fullmatch(rb"26(?:\.[0-9]+){1,2}\n", sdk.stdout), "sdk-version")
        report["sdkVersion"] = sdk.stdout.decode().strip()
        common = ["-O0", "-mmacosx-version-min=26.0", "-Wall", "-Wextra", "-Werror", "-I", str(work / "build")]
        entry = bundle("Launch Mobile Release Kit.app", "entry", entry_id)
        entry_exe = entry / "Contents/MacOS/entry"
        zero("compile-entry", compiler + common + [str(root / NATIVE / "entry.c"), "-o", str(entry_exe)], 60)
        # The ARM64 linker may already ad-hoc-sign these new task-owned images.
        zero("sign-entry", ["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", "--options", "runtime", str(entry)])
        zero("verify-entry-signature", ["/usr/bin/codesign", "--verify", "--strict", str(entry)])
        links = zero("entry-linked-images", ["/usr/bin/otool", "-L", str(entry_exe)])
        rows = links.stdout.decode("utf-8", "strict").splitlines()
        need(not links.stderr and len(rows) == 2 and rows[0] == str(entry_exe) + ":"
             and re.fullmatch(r"\s+/usr/lib/libSystem\.B\.dylib \(compatibility version [0-9.]+, current version [0-9.]+\)", rows[1]),
             "entry-system-only-linkage")
        commands = zero("entry-load-commands", ["/usr/bin/otool", "-l", str(entry_exe)])
        need(not commands.stderr and not any(marker in commands.stdout for marker in
             (b"LC_RPATH", b"LC_ROUTINES", b"LC_DYLD_ENVIRONMENT", b"__mod_init_func", b"__init_offsets"))
             and b"LC_LOAD_DYLINKER" in commands.stdout and b"name /usr/lib/dyld" in commands.stdout,
             "entry-no-payload-initializer-or-rpath")
        report["entryPreMainClosure"] = {"onlyLinkedImage": "/usr/lib/libSystem.B.dylib", "dylinker": "/usr/lib/dyld",
                                         "noRpath": True, "noModInitFunc": True, "inspectedOriginalCommands": True}
        need(not (work / "Mobile Release Kit.app").exists(), "payload-must-be-absent-for-failed-exec")
        exclusive = os.open(work / "maintenance-use.lock", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            need(signature(os.fstat(exclusive)) == gate_original, "exclusive-original")
            fcntl.flock(exclusive, fcntl.LOCK_EX | fcntl.LOCK_NB)
            refused = call("exclusive-refusal", [str(entry_exe)], 15)
            need(refused.returncode == 75 and not refused.stdout and not refused.stderr, "exclusive-refusal")
        finally:
            os.close(exclusive)  # Only this adapter's independent exclusive original.
        busy = document(read_file(work / "entry-busy.json", 4096)[0])
        record(busy, sha, ("refusedBeforeExec", "exclusiveWouldBlock"))
        need(busy["refusedBeforeExec"] and busy["exclusiveWouldBlock"], "exclusive-record")
        failed = call("real-failed-exec", [str(entry_exe)], 15)
        need(failed.returncode == 76 and not failed.stdout and not failed.stderr, "failed-exec-status")
        failure = document(read_file(work / "entry-failed-exec.json", 4096)[0])
        record(failure, sha, ("execReturnedENOENT", "originalGateStillHeld"))
        need(failure["execReturnedENOENT"] and failure["originalGateStillHeld"], "failed-exec-hold")
        exclusive = os.open(work / "maintenance-use.lock", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            need(signature(os.fstat(exclusive)) == gate_original, "post-exec-original")
            fcntl.flock(exclusive, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(exclusive)
        report["directCases"] = {"exclusiveRefusal": busy, "failedExec": failure, "exclusiveAvailableAfterOriginalExit": True}
        payload = bundle("Mobile Release Kit.app", "payload", payload_id)
        payload_exe = payload / "Contents/MacOS/payload"
        appkit = ["-fobjc-arc", "-fblocks", "-framework", "AppKit", "-framework", "Foundation"]
        zero("compile-payload", compiler + common + appkit + [str(root / NATIVE / "payload.m"), "-o", str(payload_exe)], 60)
        zero("sign-payload", ["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", "--options", "runtime", str(payload)])
        zero("verify-payload-signature", ["/usr/bin/codesign", "--verify", "--strict", str(payload)])
        observer = work / "build/observe"
        zero("compile-observer", compiler + common + appkit + [str(root / NATIVE / "observe.m"), "-o", str(observer)], 60)
        bundle_pins = {"entry": tree(entry), "payload": tree(payload), "observer": read_file(observer, 8 * 1024 * 1024)[1]}
        report["bundleFiles"] = {label: {k: {"bytes": v["bytes"], "sha256": v["sha256"]} for k, v in entries.items()}
                                  for label, entries in bundle_pins.items() if label != "observer"}
        observed = call("one-launchservices-observation", [str(observer)], 60)
        # AppKit may emit OS diagnostics. Preserve their bound/hash above, not
        # raw text or invented evidence; only the strict stdout contract counts.
        report["native"] = native_data(observed.stdout, sha)
        need(tree(entry) == bundle_pins["entry"] and tree(payload) == bundle_pins["payload"]
             and read_file(observer, 8 * 1024 * 1024)[1] == bundle_pins["observer"], "native-inputs-changed")
        report["sourcePrePostMatched"] = snapshot(root, pins) == before
        success = observed.returncode == 0 and supported_observation(report["native"]) and report["sourcePrePostMatched"]
        report["stage"] = "observed"
    except BaseException as error:
        report["error"] = str(error) if type(error) is Refused else "interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "adapter-or-owner-error"
        report["originalCallReturned"] = last_returned
        if owner is not None and isinstance(error, (owner.ProcessError, owner.ProcessInterrupted)):
            report["ownerFailure"] = {"dispatched": error.dispatched, "contained": error.contained,
                                      "cleanupComplete": getattr(error, "cleanup_complete", None)}
        success = False
    if work is not None and "work_original" in locals():
        try:
            need(signature(work.lstat())[:5] == work_original, "work-original")
            native = report["native"] or {}
            # NSRunningApplication is NOT a clean-exit/all-descendant receipt.
            # Keep synthetic app images for job retirement; never kill a PID or
            # destroy bundles solely because they disappeared from the desktop.
            report["cleanup"]["unknownStateRetained"] = inflight or not native.get("observationComplete", False)
            report["cleanup"]["applicationImagesAndTempRetained"] = True
            if not inflight and native.get("observationComplete") and native.get("terminationObserved"):
                need(shutil.rmtree.avoids_symlink_attacks, "safe-task-cleanup")
                fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    need(signature(os.fstat(fd))[:5] == work_original, "work-open-original")
                    # Only completed compiler/controller outputs and their own
                    # temp directory; app-tmp, bundles and diagnostic records
                    # remain. LaunchServices is explicitly given app-tmp, not tmp.
                    tree(work / "build"); tree(work / "tmp")
                    shutil.rmtree("build", dir_fd=fd)
                    shutil.rmtree("tmp", dir_fd=fd)
                finally:
                    os.close(fd)
                report["cleanup"]["disposableRemoved"] = True
        except BaseException:
            report["cleanup"]["error"] = "task-cleanup-refused"
            success = False
        report["feasibilityObserved"] = success
        body = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        try:
            need(len(body) <= 262144, "report-bound")
            write_new(work / "evidence/result.json", body)
        except BaseException:
            return 1
    else:
        print(json.dumps({"schemaVersion": 1, "feasibilityObserved": False, "stage": report["stage"], "error": report["error"]}, sort_keys=True))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
