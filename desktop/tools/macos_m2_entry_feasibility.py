#!/usr/bin/env python3
"""One fixed hosted full-payload boundary diagnostic, not M2 qualification.

Imports are DATA-only. Native main reuses the reviewed Aqua owner loader and
the existing original command owner. NSWorkspace app exit status remains unknown.
"""
from __future__ import annotations

import errno
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
FULL_PAYLOAD_CASE = "ls-full-payload"
MAIN_FLAGS = ("entryPidPreserved", "gateInheritedWithoutCLOEXEC", "gateMarkedCLOEXEC", "executableIsPayload")
APPKIT_RECORDS = (
    ("sharedApplication", "payload-appkit-shared.json", "shared-application-returned"),
    ("activationPolicy", "payload-appkit-policy.json", "activation-policy-evaluated"),
    ("beforeRun", "payload-appkit-before-run.json", "setup-complete-before-run"),
    ("didFinishLaunching", "payload-appkit-did-finish.json", "did-finish-launching-entered"),
    ("runReturned", "payload-appkit-run-returned.json", "run-returned"),
)
DIAGNOSTIC_RECORDS = ("entry-gate-refused.json", "entry-failed-exec.json", "payload-main.json",
                      *(name for _, name, _ in APPKIT_RECORDS))
FIXED_RECORDS = (*DIAGNOSTIC_RECORDS, "entry-busy.json", "payload-start.json", "payload-quit.json")


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


def record(value, source, flags, extra=(), *, version=1):
    need(type(value) is dict and set(value) == {"schemaVersion", "source", *flags, *extra}
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == version
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


def gate_refusal(value, source):
    """Latched original branch DATA, never an observed application exit status."""
    fields = ("case", "phase", "selectedReturnCode", "originalRootDescriptor",
              "gateOpenDescriptor", "gateOpenErrno", "gateMatchAccepted", "rejectedGateCloseReturned")
    record(value, source, (), fields)
    need(value["case"] == FULL_PAYLOAD_CASE and value["phase"] == "entry-gate-admission"
         and type(value["selectedReturnCode"]) is int and value["selectedReturnCode"] == 66
         and type(value["originalRootDescriptor"]) is int and 0 <= value["originalRootDescriptor"] < 2**31
         and type(value["gateOpenDescriptor"]) is int and -1 <= value["gateOpenDescriptor"] < 2**31,
         "gate-refusal-shape")
    if value["gateOpenDescriptor"] == -1:
        need(type(value["gateOpenErrno"]) is int and 0 < value["gateOpenErrno"] < 2**31
             and value["gateMatchAccepted"] is None and value["rejectedGateCloseReturned"] is None,
             "gate-open-failure-shape")
    else:
        need(value["gateOpenDescriptor"] != value["originalRootDescriptor"]
             and value["gateOpenErrno"] is None and value["gateMatchAccepted"] is False
             and type(value["rejectedGateCloseReturned"]) is bool, "gate-comparison-failure-shape")
    return value


def returned_exec(value, source):
    """The immediately latched errno is DATA, not an observed app exit."""
    record(value, source, ("execReturnedENOENT", "originalGateStillHeld"), ("case", "phase", "execErrno"))
    need(value["case"] == FULL_PAYLOAD_CASE and value["phase"] == "entry-exec-returned"
         and type(value["execErrno"]) is int and 0 < value["execErrno"] < 2**31
         and value["execReturnedENOENT"] is (value["execErrno"] == errno.ENOENT), "returned-exec-shape")
    return value


def payload_main(value, source):
    """One already-admitted-root main outcome; no missing-witness inference."""
    record(value, source, (), ("case", "phase", "selectedReturnCode", "gateMatchAccepted", *MAIN_FLAGS))
    need(value["case"] == FULL_PAYLOAD_CASE and type(value["phase"]) is str
         and value["phase"] in ("main-gate-refused", "main-handoff-refused", "main-admitted-before-appkit"),
         "payload-main-phase")
    if value["phase"] == "main-gate-refused":
        need(type(value["selectedReturnCode"]) is int and value["selectedReturnCode"] == 65
             and value["gateMatchAccepted"] is False and all(value[k] is None for k in MAIN_FLAGS),
             "payload-main-gate-shape")
    else:
        need(value["gateMatchAccepted"] is True and all(type(value[k]) is bool for k in MAIN_FLAGS),
             "payload-main-handoff-shape")
        accepted = all(value[k] for k in MAIN_FLAGS[:3])
        need((value["phase"] == "main-handoff-refused"
              and type(value["selectedReturnCode"]) is int and value["selectedReturnCode"] == 66 and not accepted)
             or (value["phase"] == "main-admitted-before-appkit"
                 and value["selectedReturnCode"] is None and accepted), "payload-main-original-predicate")
    return value


def appkit_progress(value, source):
    """Five nullable fixed-site records, not an event log or a completion claim."""
    need(type(value) is dict and set(value) == {slot for slot, _, _ in APPKIT_RECORDS},
         "appkit-progress-slots")
    for slot, _name, phase in APPKIT_RECORDS:
        row = value[slot]
        if row is None:
            continue
        is_policy = slot == "activationPolicy"
        extra = ("policyBefore", "policySwitchAttempted", "policyAfter") if is_policy else ()
        record(row, source, (), ("case", "phase", "policySwitchAccepted", "selectedReturnCode", *extra),
               version=2 if is_policy else 1)
        need(row["case"] == FULL_PAYLOAD_CASE and type(row["phase"]) is str and row["phase"] == phase,
             "appkit-progress-phase")
        if is_policy:
            before, after = row["policyBefore"], row["policyAfter"]
            attempted, accepted = row["policySwitchAttempted"], row["policySwitchAccepted"]
            need(type(before) is int and -(2**63) <= before < 2**63
                 and type(attempted) is bool and attempted is (before in (1, 2)), "appkit-progress-policy")
            if not attempted:
                need(accepted is None and after is None, "appkit-progress-policy")
                selected = None if before == 0 else 67
            else:
                need(type(accepted) is bool, "appkit-progress-policy")
                if not accepted:
                    need(after is None, "appkit-progress-policy")
                    selected = 67
                else:
                    need(type(after) is int and -(2**63) <= after < 2**63, "appkit-progress-policy")
                    selected = None if after == 0 else 67
        else:
            need(row["policySwitchAccepted"] is None, "appkit-progress-policy")
            selected = 74 if slot == "runReturned" else None
        need((selected is None and row["selectedReturnCode"] is None)
             or (type(row["selectedReturnCode"]) is int and row["selectedReturnCode"] == selected),
             "appkit-progress-selected-return")
    return value


def boundary_diagnostic(native, original_status, gate, failed, main, source, progress=None):
    """Known phase DATA can survive an incomplete diagnostic; no pre-main guess."""
    need(type(original_status) is int and 0 <= original_status <= 255, "diagnostic-owner-status")
    if gate is not None:
        gate_refusal(gate, source)
    if failed is not None:
        returned_exec(failed, source)
    if main is not None:
        payload_main(main, source)
    need(sum(value is not None for value in (gate, failed, main)) <= 1, "diagnostic-conflicting-outcomes")
    admitted = main is not None and main["phase"] == "main-admitted-before-appkit"
    if gate is not None or failed is not None or (main is not None and not admitted):
        need(native["payloadStart"] is None and native["payloadQuit"] is None, "diagnostic-impossible-phase-records")
    if admitted and native["payloadStart"] is not None:
        need(all(main[k] is native["payloadStart"][k] for k in MAIN_FLAGS), "diagnostic-main-start-facts")
    progress = appkit_progress({slot: None for slot, _, _ in APPKIT_RECORDS}
                               if progress is None else progress, source)
    if any(row is not None for row in progress.values()):
        need(gate is None and failed is None and (main is None or admitted),
             "diagnostic-appkit-after-refusal")
    policy = progress["activationPolicy"]
    policy_refused = policy is not None and policy["selectedReturnCode"] == 67
    if policy_refused:
        need(all(progress[slot] is None for slot in ("beforeRun", "didFinishLaunching", "runReturned"))
             and native["payloadStart"] is None and native["payloadQuit"] is None,
             "diagnostic-appkit-policy-conflict")
    outcome, branch_accepted = "unresolved", False
    if gate is not None:
        outcome, branch_accepted = "entry-gate-refused", gate["rejectedGateCloseReturned"] is not False
    elif failed is not None:
        outcome, branch_accepted = "entry-exec-returned", failed["originalGateStillHeld"]
    elif main is not None:
        outcome, branch_accepted = main["phase"], True
    true_flags = ("launchRequested", "launchReferenceReturned", "terminationObserved",
                  "exclusiveAvailableAfterTermination", "rootCloseReturned", "timely")
    false_flags = ("launchErrorReported", "workDeadlineFailed", "normalQuitRequestSent",
                   "observationComplete", "referencePIDMatchesPayload", "exclusiveBlockedWhilePayloadAlive",
                   *(flag for pair in REFERENCE_IDENTITY_PAIRS for flag in pair))
    early = (original_status == 1 and native["firstFailure"] == "payload-terminated-before-observation"
             and all(native[k] for k in true_flags) and not any(native[k] for k in false_flags)
             and all(native[k] == 1 for k in COUNTS)
             and native["payloadStart"] is None and native["payloadQuit"] is None)
    complete = admitted and original_status == 0 and supported_observation(native)
    complete = complete and not policy_refused and progress["runReturned"] is None
    if complete:
        outcome = "full-payload-observed"
    return {"case": FULL_PAYLOAD_CASE, "boundaryOutcome": outcome, "entryGateRefusal": gate,
            "failedExec": failed, "payloadMain": main, "appKitProgress": progress,
            "expectedBoundaryObserved": branch_accepted and (early or complete)}


def require_absent(path, reason):
    try:
        path.lstat()  # A dangling link or any other occupant is not absence.
    except FileNotFoundError:
        return
    raise Refused(reason)


def read_diagnostic(path, uid, gid):
    need(path.name in DIAGNOSTIC_RECORDS, "diagnostic-record-name")
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    # A name seen above but lost during read/proof is an error, never missing.
    body, original = read_file(path, 4096)
    need(original[2] == stat.S_IFREG | 0o400 and original[3:5] == (uid, gid)
         and original[5] == 1, "diagnostic-record-original")
    return document(body)


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


def fixture_stat(original):
    """Bounded synthetic diagnostics, never a custody or finality receipt."""
    return dict(zip(("device", "inode", "mode", "uid", "gid", "links", "bytes"), original[:7]))


def prepare_work_root(work, uid, gid, diagnostics):
    """Initialize only the newly created original; never adopt or repair."""
    parent = created = None
    failure = None
    diagnostics.update(accountUid=uid, accountGid=gid, rootCreated=False,
                       initialGroupSelected=False, rootPrepared=False, closeFailures=[])
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        diagnostics["stage"] = "parent-admission"
        parent = os.open(work.parent, flags)
        parent_original = signature(os.fstat(parent))
        diagnostics["parent"] = fixture_stat(parent_original)
        need(parent_original[2] == stat.S_IFDIR | 0o1777 and parent_original[3] == 0
             and signature(os.stat(work.parent, follow_symlinks=False))[:5] == parent_original[:5],
             "fixture-parent-original")
        diagnostics["stage"] = "root-create"
        os.mkdir(work.name, 0o700, dir_fd=parent)  # Occupied names always refuse.
        diagnostics["rootCreated"] = True
        created = os.open(work.name, flags, dir_fd=parent)
        diagnostics["stage"] = "root-custody"
        original = signature(os.fstat(created))
        diagnostics["initialRoot"] = fixture_stat(original)
        need(original[2] == stat.S_IFDIR | 0o700 and original[3] == uid
             and signature(os.stat(work.name, dir_fd=parent, follow_symlinks=False)) == original,
             "fixture-created-root-custody")
        # Darwin inherits the parent directory's group, even without setgid.
        # Select the group on this fresh private original before any children.
        diagnostics["stage"] = "root-group-selection"
        if original[4] != gid:
            os.fchown(created, -1, gid)
            diagnostics["initialGroupSelected"] = True
        current = signature(os.fstat(created))
        diagnostics["finalRoot"] = fixture_stat(current)
        need(current[:4] == original[:4] and current[4] == gid and current[5:8] == original[5:8]
             and (diagnostics["initialGroupSelected"] or current == original)
             and signature(os.stat(work.name, dir_fd=parent, follow_symlinks=False)) == current,
             "fixture-created-root-group")
    except BaseException as error:
        failure = error
    finally:
        # Each successful open has exactly one consuming close, even if the
        # other close or an earlier operation failed. Never retry an FD number.
        for label, fd in (("root", created), ("parent", parent)):
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException:
                    diagnostics["closeFailures"].append(label)
                    if failure is None:
                        failure = Refused("fixture-" + label + "-close")
    if failure is not None:
        raise failure
    diagnostics.update(stage="root-prepared", rootPrepared=True)
    return current[:5]  # Establish the cleanup original only after selection.


def admit_gate(path, uid, gid, diagnostics):
    body, original = read_file(path, 0)  # Original FD/name proof, no links or data.
    diagnostics["gate"] = fixture_stat(original)
    need(not body and original[2] == stat.S_IFREG | 0o444 and original[3:5] == (uid, gid)
         and original[5:7] == (1, 0), "fixture-gate-shape-owner")
    return original


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
    report = {"schemaVersion": 1, "scope": "m2-full-payload-boundary-diagnostic-only", "feasibilityObserved": False,
              "installedProductQualified": False, "tauriQualified": False, "credentialQualified": False,
              "maintenanceAvailable": False, "diagnosticComplete": False, "diagnostic": None,
              "commands": [], "native": None,
              "stage": "admission", "error": None, "sourcePrePostMatched": False,
              "cleanup": {"disposableRemoved": False, "unknownStateRetained": False,
                          "applicationImagesAndTempRetained": False, "error": None}}
    owner = work = before = bundle_pins = None
    inflight = False
    last_returned = False
    diagnostic_complete = False
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
        report["stage"] = "fixture-root-preparation"
        report["fixtureAdmission"] = {}
        work_original = prepare_work_root(work, uid, gid, report["fixtureAdmission"])
        for name in ("build", "tmp", "app-tmp", "evidence"):
            (work / name).mkdir(mode=0o700)
        write_new(work / "maintenance-use.lock", b"", 0o444)
        report["stage"] = "fixture-gate-admission"
        gate_original = admit_gate(work / "maintenance-use.lock", uid, gid, report["fixtureAdmission"])
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
            need(signature(work.lstat())[:5] == work_original, "work-changed")
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
        appkit = ["-fobjc-arc", "-fblocks", "-framework", "AppKit", "-framework", "Foundation"]
        payload = bundle("Mobile Release Kit.app", "payload", payload_id)
        payload_exe = payload / "Contents/MacOS/payload"
        zero("compile-payload", compiler + common + appkit + [str(root / NATIVE / "payload.m"), "-o", str(payload_exe)], 60)
        zero("sign-payload", ["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", "--options", "runtime", str(payload)])
        zero("verify-payload-signature", ["/usr/bin/codesign", "--verify", "--strict", str(payload)])
        observer = work / "build/observe"
        zero("compile-observer", compiler + common + appkit + [str(root / NATIVE / "observe.m"), "-o", str(observer)], 60)
        bundle_pins = {"entry": tree(entry), "payload": tree(payload), "observer": read_file(observer, 8 * 1024 * 1024)[1]}
        report["bundleFiles"] = {label: {k: {"bytes": v["bytes"], "sha256": v["sha256"]} for k, v in entries.items()}
                                  for label, entries in bundle_pins.items() if label != "observer"}
        # Fresh full payload, one entry invocation through LS, no direct controls.
        # No previous publication or incomplete staging file may seed this call.
        for name in FIXED_RECORDS:
            require_absent(work / name, "boundary-diagnostic-name-occupied")
            require_absent(work / ("." + name + ".inflight"), "boundary-diagnostic-staging-occupied")
        observed = call("one-launchservices-observation", [str(observer)], 60)
        # AppKit may emit OS diagnostics. Preserve their bound/hash above, not
        # raw text or invented evidence; only the strict stdout contract counts.
        report["native"] = native_data(observed.stdout, sha)
        need(tree(entry) == bundle_pins["entry"] and tree(payload) == bundle_pins["payload"]
             and read_file(observer, 8 * 1024 * 1024)[1] == bundle_pins["observer"], "native-inputs-changed")
        gate = read_diagnostic(work / "entry-gate-refused.json", uid, gid)
        failed = read_diagnostic(work / "entry-failed-exec.json", uid, gid)
        main_record = read_diagnostic(work / "payload-main.json", uid, gid)
        progress = {slot: read_diagnostic(work / name, uid, gid) for slot, name, _ in APPKIT_RECORDS}
        report["diagnostic"] = boundary_diagnostic(report["native"], observed.returncode, gate, failed, main_record, sha,
                                                   progress=progress)
        check_sources()
        report["sourcePrePostMatched"] = snapshot(root, pins) == before
        diagnostic_complete = report["diagnostic"]["expectedBoundaryObserved"] and report["sourcePrePostMatched"]
        report["stage"] = "full-payload-boundary-observed"
    except BaseException as error:
        report["error"] = str(error) if type(error) is Refused else "interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "adapter-or-owner-error"
        report["originalCallReturned"] = last_returned
        if owner is not None and isinstance(error, (owner.ProcessError, owner.ProcessInterrupted)):
            report["ownerFailure"] = {"dispatched": error.dispatched, "contained": error.contained,
                                      "cleanupComplete": getattr(error, "cleanup_complete", None)}
        diagnostic_complete = False
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
            diagnostic_complete = False
        report["diagnosticComplete"] = diagnostic_complete
        body = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        try:
            need(len(body) <= 262144, "report-bound")
            write_new(work / "evidence/result.json", body)
        except BaseException:
            return 1
    else:
        print(json.dumps({"schemaVersion": 1, "scope": "m2-full-payload-boundary-diagnostic-only",
                          "diagnosticComplete": False, "feasibilityObserved": False, "stage": report["stage"],
                          "error": report["error"], "fixtureAdmission": report.get("fixtureAdmission")}, sort_keys=True))
    return 0 if diagnostic_complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
