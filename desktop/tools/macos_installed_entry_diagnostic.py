#!/usr/bin/env python3
"""Two fixed entry diagnostics and a separate fixed package-reuse UI duty.

Only main loads the pinned current stager/command owner. Import is inert stdlib.
The reused application and diagnostic harness deliberately have different SHAs.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import threading
import zipfile

REPO = "Apdelrahman1911/mobile-release-kit"
REF = "refs/heads/verify/desktop-macos-entry-diagnostic"
UI_REF = "refs/heads/verify/desktop-macos-packaged-ui"
UI_HELPER = "desktop/tools/macos_normal_ui_runner.py"
UI_DEVELOPER = "/Applications/Xcode.app/Contents/Developer"
PACKAGE_BYTES = 50964188
PACKAGE_SHA = "618c873f0b841b54faceae9e5ad1ca073a94215a1a53cee0bf28c3aa17361119"
WORKFLOW = ".github/workflows/desktop-macos-entry-diagnostic.yml"
APPLICATION_SOURCE = "53850a9fd94768a2521f2634db6121550dbdd71c"
SOURCE_RUN = "37143431561"
SOURCE_ATTEMPT = "1"
ARTIFACT_ID = "11281078057"
ARCHIVE_BYTES = 50972943
ARCHIVE_SHA = "dfb46e23f7b397facc1a9b69b77d1440960fb846bedc90a573f2410b230255d0"
ENTRY = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/MacOS/mrk-macos-entry"
INSTALL_ROOT = Path("/Library/Application Support/MobileReleaseKit")
STAGER = "desktop/tools/stage_macos_installed.py"
LOADER = "desktop/tools/macos_aqua_qualification.py"
NATIVE = "desktop/native/macos-installed-entry-diagnostic/observe.m"
PINS = {
    UI_HELPER: "207e473f346c4643e7e56d343625cd86eb99ecdfc44256676e558cecbeaa68e2",
    STAGER: "03a400dd9ba5086762ff06535004a56f8828592a38ae564d96ef0e46b6109490",
    LOADER: "1271fc4765e6709e8c2b7d4f6094c4437d8642f91fa140c795eb49731b8a816b",
    "desktop/macos-installed-inputs/build-release.json": "a71990f4eba76fb6c05e011799999decf8620c5ad8ea0471fb13cada37646630",
    "desktop/macos-installed-inputs/postinstall": "902be9b2b136b84bae89e50b140535459fa62bb0b4da82098b1a7152740d4121",
    "desktop/native/macos-installed-entry/gate.c": "68c8212448bcab2fccf2b530d8f7eda2aa41e245e81cb6545c9d67424bca3e8f",
    "desktop/native/macos-installed-entry/gate.h": "871ec5bc062975901322e0ef55a2de417ec61a9ea2ce7fdd3d1091a490b8e390",
    "desktop/native/macos-installed-entry/fixed_paths.h": "8a2e46a3543d476c1b90e30e87a5fdb5c07bbec27f275485a0e8f98b06540af3",
    "desktop/native/macos-installed-native/src/native.m": "75a6f06f7d29626883a864be4d827a4682a71f8eb58334166a2def377dd0ea59",
    "src/mobile_release/owned_process.py": "d832b81894372f3c48b110f6e381fe00f6d71b75940f63a3d7eb5d61c1e2fad1",
    "src/mobile_release/_command_process.py": "1ea5035578ae8ba0da31367f018d02b3669529077a65e2970cf92d1cc084b1c5",
    "src/mobile_release/_native_process.py": "70c380adde3c2bc06a0985761f0f877355bb56ef09ad506440da93fd4e4ba3b4",
    "src/mobile_release/cancellation.py": "5f469444f42b5ad6a69ecce8161a7d83e67303c92a221a31f88c079f4ff29d35",
}
LIMIT = 65536
UI_FAILURE_LIMIT = 4096
PREFIX = b"MRK_INSTALLED_ENTRY_DIAGNOSTIC="
BOOLS = frozenset("launchRequested launchReferenceReturned launchErrorReported workDeadlineFailed clockUnavailable normalTerminateRequested forceTerminateRequested terminationObserved ancestorCloseReturned probeClosesReturned finalDeadlineMet observationComplete normalQuitQualified fullUIQualified fullM2Qualified productReady".split())
NULLABLE_BOOLS = frozenset("referenceTerminatedAtObservation referenceFinishedLaunching referenceActive normalTerminateReturned forceTerminateReturned".split())
COUNTS = frozenset("completionCount completionBodyDoneCount completionHandoffCount".split())
IDENTITIES = frozenset("referenceBundle referenceBundleIdentifier referenceExecutable".split())
GATES = frozenset("gateBefore gateWhileOriginalLive gateAfterTermination".split())
FAILURES = frozenset("none account gate-baseline clock launch-exception launch-completion duplicate-completion original-terminated observation-deadline native-exception cleanup-exception termination-unobserved gate-postprobe descriptor-close final-deadline publication".split())
ENTRY_REFUSALS = frozenset((64, 65, 66, 67, 68, 69, 70, 71, 72, 75, 76))


class Refused(Exception):
    """Closed public label only; never echo arbitrary exception/path text."""


def need(value, reason):
    if not value:
        raise Refused(reason)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def full9(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)



def ui_public_toolchain(values):
    """Only bounded public version tokens and fixed toolchain path shapes."""
    applications = re.escape(str(Path(UI_DEVELOPER).parent.parent.parent))
    patterns = {
        "xcode": r"Xcode [0-9]+(?:\.[0-9]+)*\nBuild version [0-9A-Za-z]+",
        "sdkVersion": r"[0-9]+(?:\.[0-9]+)*",
        "sdkBuild": r"[0-9A-Za-z]+",
        "sdkPath": applications + r"/Xcode(?:_[0-9]+(?:\.[0-9]+)*)?\.app/Contents/Developer"
                   r"/Platforms/MacOSX\.platform/Developer/SDKs/MacOSX(?:[0-9]+(?:\.[0-9]+)*)?\.sdk",
    }
    return {key: value for key, value in values.items()
            if key in patterns and len(value) <= 512 and re.fullmatch(patterns[key], value)}


def ui_failure_unavailable():
    return {"schemaVersion": 1, "scope": "captured-ui-failure-diagnostics-only", "status": "unavailable",
            "errorCodes": [], "sourceFailures": [], "findingsTruncated": False,
            "markers": {"selectedCaseStarted": False, "selectedCaseFailed": False,
                        "testExecuteFailed": False, "testingFailed": False, "xcodebuildError": False}}


def ui_failure_diagnostics(stdout, stderr):
    """Closed textual observations only: never assertion/reason tails or native-cause authority."""
    value = ui_failure_unavailable()
    if type(stdout) is not bytes or type(stderr) is not bytes or len(stdout) + len(stderr) > LIMIT:
        return value
    domains = {domain.encode("ascii"): domain for domain in (
        "NSCocoaErrorDomain", "NSPOSIXErrorDomain", "NSOSStatusErrorDomain", "NSMachErrorDomain",
        "XCTestErrorDomain", "XCTRunnerErrorDomain", "com.apple.dt.xctest.error",
        "IDETestOperationsObserverErrorDomain", "IDEFoundationErrorDomain", "RBSRequestErrorDomain",
        "RBSServiceErrorDomain", "FBSOpenApplicationServiceErrorDomain", "FBSOpenApplicationErrorDomain",
        "IXUserPresentableErrorDomain")}
    case = re.escape(b"-[MRKNormalAppUITests.NormalAppUITests testPackagedEntryLaunchCancelAndQuit]")
    codes = (rb"(?:\A|(?<=[ \t\r\n({\x5b]))Error[ \t]{1,8}Domain=("
             + b"|".join(re.escape(domain) for domain in domains)
             + rb")[ \t]{1,8}Code=(-?(?:0|[1-9][0-9]{0,9}))(?=\Z|[ \t\r\n,;\"')}\x5d])")
    locations = (rb"(?:\A|(?<=[/ \t\r\n]))NormalAppUITests\.swift:([1-9][0-9]{0,4})"
                 rb"(?::([1-9][0-9]{0,3}))?:[ \t]{1,8}error:[ \t]{1,8}"
                 + case + rb"[ \t]{0,8}:")
    markers = {
        "selectedCaseStarted": rb"(?m)^Test Case '" + case + rb"' started\.\r?$",
        "selectedCaseFailed": (rb"(?m)^Test Case '" + case
                               + rb"' failed(?: \([0-9]{1,6}(?:\.[0-9]{1,9})? seconds\))?\.\r?$"),
        "testExecuteFailed": rb"(?m)^\*\* TEST EXECUTE FAILED \*\*\r?$",
        "testingFailed": rb"(?m)^Testing failed:",
        "xcodebuildError": rb"(?m)^xcodebuild: error:",
    }

    def retain(key, finding, maximum):
        # Only retained entries are remembered; neither descriptions nor an
        # unbounded set of discarded findings accumulates.
        if finding not in value[key]:
            if len(value[key]) < maximum:
                value[key].append(finding)
            else:
                value["findingsTruncated"] = True

    for stream, body in (("stdout", stdout), ("stderr", stderr)):
        for key, pattern in markers.items():
            value["markers"][key] = value["markers"][key] or re.search(pattern, body) is not None
        for match in re.finditer(codes, body):
            token = match.group(2)
            code = int(token)
            if token != b"-0" and -2147483648 <= code <= 2147483647:
                retain("errorCodes", {"stream": stream, "domain": domains[match.group(1)], "code": code}, 8)
        for match in re.finditer(locations, body):
            line = int(match.group(1))
            column = int(match.group(2)) if match.group(2) is not None else None
            if line <= 65535 and (column is None or column <= 4096):
                retain("sourceFailures", {"stream": stream, "source": "NormalAppUITests.swift",
                       "test": "testPackagedEntryLaunchCancelAndQuit", "line": line, "column": column}, 4)
    value["status"] = "classified" if value["errorCodes"] or value["sourceFailures"] else "unclassified"
    return value


class SelectedUIToolchain:
    """Bind only the fixed selected Xcode alias; release originals before build."""

    def __init__(self, helper, report):
        self.helper = helper
        # All slots exist before any acquisition; no FD is discovered or retried.
        self.held = {"developer": None, "sdk-parent": None, "sdk": None}
        self.bindings = {}
        self.closed = False
        self.state = {"admitted": False, "check": "selected-developer",
                      "originalClosesCompleted": False, "closeFailures": []}
        report["toolchainAdmission"] = self.state

    def hold(self, role, path):
        need(not self.closed and role in self.held and self.held[role] is None, "ui-toolchain-custody")
        self.held[role] = self.helper.open_directory(path)
        identity = full9(os.fstat(self.held[role]))
        need(stat.S_ISDIR(identity[2]) and full9(path.lstat()) == identity, "ui-toolchain-original")
        self.bindings[role] = (path, identity)

    def __enter__(self):
        try:
            self.logical = Path(UI_DEVELOPER)
            self.application = self.logical.parent.parent
            self.alias_identity = full9(self.application.lstat())
            self.physical = self.logical.resolve(strict=True)
            physical_app = self.physical.parent.parent
            need(self.application.name == "Xcode.app"
                 and self.logical == self.application / "Contents/Developer"
                 and self.physical == physical_app / "Contents/Developer"
                 and physical_app.parent == self.application.parent
                 and (physical_app.name == "Xcode.app"
                      or re.fullmatch(r"Xcode_26(?:\.[0-9]+)*\.app", physical_app.name)),
                 "ui-selected-developer-location")
            if stat.S_ISLNK(self.alias_identity[2]):
                target = Path(os.readlink(self.application))
                need(str(target) == os.readlink(self.application)
                     and (target == physical_app or target == Path(physical_app.name)),
                     "ui-selected-developer-alias")
            else:
                need(stat.S_ISDIR(self.alias_identity[2]) and physical_app == self.application,
                     "ui-selected-developer-directory")
            self.hold("developer", self.physical)
            self.check()
            self.state["check"] = "toolchain-queries"
            return self
        except BaseException:
            self.close()
            raise

    def check(self):
        need(full9(self.application.lstat()) == self.alias_identity
             and self.logical.resolve(strict=True) == self.physical
             and full9(self.logical.stat()) == self.bindings["developer"][1],
             "ui-selected-developer-changed")
        for role, (path, identity) in self.bindings.items():
            need(full9(os.fstat(self.held[role])) == identity == full9(path.lstat()),
                 "ui-toolchain-original-changed")
        if "sdk" in self.bindings:
            path, identity = self.bindings["sdk"]
            need(full9(self.sdk_named.lstat()) == self.sdk_alias_identity
                 and self.sdk_logical.resolve(strict=True) == path
                 and full9(self.sdk_logical.stat()) == identity,
                 "ui-selected-sdk-changed")
        need(full9(self.application.lstat()) == self.alias_identity, "ui-selected-developer-changed")

    def admit_sdk(self, sdk_text, version):
        self.state["check"] = "selected-sdk"
        self.check()
        suffix = "Platforms/MacOSX.platform/Developer/SDKs"
        parent = self.physical / suffix
        candidate = Path(sdk_text)
        names = {"MacOSX.sdk", "MacOSX" + version + ".sdk"}
        need(sdk_text == str(candidate) and candidate.parent in {parent, self.logical / suffix}
             and candidate.name in names, "ui-sdk-selected-path")
        self.hold("sdk-parent", parent)  # No-follow traversal rejects redirected SDKs/parents.
        self.sdk_named = parent / candidate.name
        self.sdk_alias_identity = full9(self.sdk_named.lstat())
        physical_sdk = candidate.resolve(strict=True)
        need(physical_sdk.parent == parent and physical_sdk.name in names, "ui-sdk-selected-location")
        if stat.S_ISLNK(self.sdk_alias_identity[2]):
            target = Path(os.readlink(self.sdk_named))
            need(str(target) == os.readlink(self.sdk_named)
                 and (target == physical_sdk or target == Path(physical_sdk.name)), "ui-sdk-terminal-alias")
        else:
            need(stat.S_ISDIR(self.sdk_alias_identity[2]) and physical_sdk == self.sdk_named,
                 "ui-sdk-directory")
        self.sdk_logical = candidate
        self.hold("sdk", physical_sdk)
        self.check()

    def close(self):
        if self.closed:
            return
        self.closed = True
        for role in self.held:
            fd, self.held[role] = self.held[role], None  # Consume once before close.
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException:
                    self.state["closeFailures"].append(role)
        self.state["originalClosesCompleted"] = not self.state["closeFailures"]
        need(self.state["originalClosesCompleted"], "ui-toolchain-close")

    def __exit__(self, kind, value, traceback):
        try:
            if kind is None:
                self.state["check"] = "pre-build-identity"
                need(set(self.bindings) == set(self.held), "ui-toolchain-incomplete")
                self.check()
        finally:
            self.close()  # A close failure blocks build, also after a body/check failure.
        if kind is None:
            self.state.update(admitted=True, check="admitted")
        return False


def read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
             "file-policy")
        chunks, count = [], 0
        while True:
            block = os.read(fd, min(65536, limit + 1 - count))
            if not block:
                break
            chunks.append(block); count += len(block)
            need(count <= limit, "file-bound")
        need(count == before.st_size and full9(before) == full9(os.fstat(fd))
             == full9(os.stat(path, follow_symlinks=False)), "file-changed")
        return b"".join(chunks), full9(before)
    finally:
        os.close(fd)  # One consuming close; no retry or reused number.


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def document(body, limit=LIMIT):
    need(type(body) is bytes and 0 < len(body) <= limit, "json-bound")
    value = json.loads(body.decode("utf-8", "strict"), object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(Refused("json-number")))
    need(type(value) is dict, "json-object")
    return value


def encoded(value, limit=LIMIT):
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii") + b"\n"
    need(len(body) <= limit, "report-bound")
    return body


def write_new(path, body, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        offset = 0
        while offset < len(body):
            count = os.write(fd, body[offset:])
            need(count > 0, "write-return")
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)


def preview(body):
    value = document(body, 32768)
    fixed = {
        "schemaVersion": 1, "scope": "normal-macos-early-preview", "sourceCommit": APPLICATION_SOURCE,
        "workflow": ".github/workflows/desktop-macos-installed.yml", "runId": SOURCE_RUN,
        "runAttempt": SOURCE_ATTEMPT, "platform": "macOS26-arm64", "instrumented": False,
        "entryBundleIdentifier": "dev.mobile-release-kit.desktop.entry",
        "payloadBundleIdentifier": "dev.mobile-release-kit.desktop",
        "ordinaryEntryRoute": "unexecuted", "directPayloadPreMain": "unqualified",
        "fullM2Qualified": False, "maintenanceQualified": False, "normalBuild": "passed",
        "packageAudit": "passed", "installationReadback": "passed", "automaticWindowOpen": "unexecuted",
        "normalQuit": "unexecuted", "manualUIAcceptance": "pending",
        "unexecutedReason": "original-normal-app-quit-custody-not-established",
        "fullUIQualified": False, "distributionQualified": False, "productReady": False,
    }
    hashes = {"packageSha256", "runtimeManifestSha256", "installerInventorySha256",
              "normalBinaryBeforeSigningSha256", "signedAppBinarySha256", "signedEntryBinarySha256"}
    need(set(value) == set(fixed) | hashes | {"sourceTree", "packageSize"}, "preview-keys")
    for key, expected in fixed.items():
        need(type(value[key]) is type(expected) and value[key] == expected, "preview-fixed-binding")
    need(all(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{64}", value[key]) for key in hashes)
         and type(value["sourceTree"]) is str and re.fullmatch(r"[0-9a-f]{40}", value["sourceTree"])
         and type(value["packageSize"]) is int and 0 < value["packageSize"] <= 64 * 1024 * 1024,
         "preview-value-binding")
    return value


def archive_members(body):
    need(len(body) == ARCHIVE_BYTES and digest(body) == ARCHIVE_SHA, "artifact-bytes")
    with zipfile.ZipFile(io.BytesIO(body), "r") as archive:
        rows = archive.infolist()
        need(len(rows) == 3 and {row.filename for row in rows} == {"MobileReleaseKit.pkg", "README.md", "PREVIEW.json"},
             "artifact-roster")
        result = {}
        for row in rows:
            mode = row.external_attr >> 16
            maximum = 64 * 1024 * 1024 if row.filename == "MobileReleaseKit.pkg" else 32768
            need(not row.is_dir() and stat.S_IFMT(mode) in (0, stat.S_IFREG)
                 and not row.flag_bits & 1 and row.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                 and 0 < row.file_size <= maximum and row.compress_size <= ARCHIVE_BYTES,
                 "artifact-member-policy")
            data = archive.read(row)
            need(len(data) == row.file_size, "artifact-member-size")
            result[row.filename] = data
    selected = preview(result["PREVIEW.json"])
    package = result["MobileReleaseKit.pkg"]
    need(len(package) == selected["packageSize"] and digest(package) == selected["packageSha256"],
         "inner-package-binding")
    return result, selected


def package_inventory(stage, package, selected, postinstall):
    members = stage.xar_members(package)
    need(set(members) == {"PackageInfo", "Scripts"}, "package-roster")
    stage.package_info(members["PackageInfo"])
    scripts = members["Scripts"]
    if scripts[:2] == b"\x1f\x8b":
        scripts = stage.inflate(scripts, stage.MAX_BYTES, gzip=True)
    entries = stage.cpio_members(scripts)
    need(entries.get("postinstall") == (postinstall, 0o555), "postinstall-bytes")
    installer = entries.get("mrk-macos-install")
    need(type(installer) is tuple and len(installer) == 2 and type(installer[0]) is bytes
         and installer[1] == 0o555, "installer-member")
    stage.macho(installer[0])
    inventory = entries.get("input/install-inventory.json")
    need(type(inventory) is tuple and len(inventory) == 2 and inventory[1] == 0o444
         and type(inventory[0]) is bytes, "inventory-member")
    rows = stage.observation_inventory_bytes(inventory[0], selected["installerInventorySha256"],
                                              selected["runtimeManifestSha256"])
    files = {"postinstall", "mrk-macos-install", "input/install-inventory.json"} | {"input/" + name for name in rows}
    directories = stage.directories(files)
    need(set(entries) == files | set(directories), "complete-scripts-roster")
    need(all(entries[name] == (None, 0o555) for name in directories), "scripts-directories")
    for name, expected in rows.items():
        data, mode = entries["input/" + name]
        need(type(data) is bytes and len(data) == expected["size"] and digest(data) == expected["sha256"]
             and mode == (0o555 if expected["executable"] else 0o444), "scripts-inventory-correspondence")
    need(rows["app/" + stage.ENTRY_BINARY]["sha256"] == selected["signedEntryBinarySha256"]
         and rows["app/" + stage.APP_BINARY]["sha256"] == selected["signedAppBinarySha256"], "preview-image-binding")
    return inventory[0], {"fileCount": len(rows), "installerSha256": digest(installer[0]),
                          "packageInfoSha256": digest(members["PackageInfo"])}


def native_result(body, source):
    need(body.startswith(PREFIX) and body.endswith(b"\n") and body.count(b"\n") == 1
         and len(body) <= len(PREFIX) + 8193, "native-frame")
    value = document(body[len(PREFIX):-1], 8192)
    extra = {"schemaVersion", "scope", "diagnosticSource", "applicationSource", "launchErrorDomain", "launchErrorCode",
             "originalAppExitStatus", "allWorkerFinality", "firstFailure"}
    need(set(value) == BOOLS | NULLABLE_BOOLS | COUNTS | IDENTITIES | GATES | extra, "native-keys")
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["scope"] == "ordinary-installed-entry-launch-diagnostic-v1"
         and value["diagnosticSource"] == source and value["applicationSource"] == APPLICATION_SOURCE,
         "native-source")
    need(all(type(value[k]) is bool for k in BOOLS), "native-boolean")
    need(all(value[k] is None or type(value[k]) is bool for k in NULLABLE_BOOLS), "native-nullable-boolean")
    need(all(type(value[k]) is int and 0 <= value[k] <= 2 for k in COUNTS), "native-count")
    need(all(type(value[k]) is str and value[k] in {"unavailable", "entry", "payload", "other"} for k in IDENTITIES)
         and all(type(value[k]) is str and value[k] in {"unobserved", "free", "busy", "error"} for k in GATES), "native-enum")
    need(type(value["launchErrorDomain"]) is str and value["launchErrorDomain"] in {"none", "cocoa", "osstatus", "posix", "url", "other"}
         and (value["launchErrorCode"] is None or type(value["launchErrorCode"]) is int
              and -(2**31) <= value["launchErrorCode"] < 2**31)
         and value["originalAppExitStatus"] is None and value["allWorkerFinality"] == "not-established"
         and type(value["firstFailure"]) is str and value["firstFailure"] in FAILURES, "native-error-scope")
    need(not any(value[k] for k in ("normalQuitQualified", "fullUIQualified", "fullM2Qualified", "productReady")),
         "native-qualification")
    need(value["completionHandoffCount"] <= value["completionCount"]
         and value["completionBodyDoneCount"] <= value["completionCount"], "native-callback-order")
    need(not value["launchReferenceReturned"] or value["launchRequested"] and value["completionHandoffCount"] >= 1,
         "native-original-reference")
    need(not value["launchErrorReported"] or value["completionHandoffCount"] >= 1, "native-error-handoff")
    need(value["launchErrorReported"] == (value["launchErrorDomain"] != "none")
         and (value["launchErrorReported"] or value["launchErrorCode"] is None), "native-error-correspondence")
    for request, returned in (("normalTerminateRequested", "normalTerminateReturned"), ("forceTerminateRequested", "forceTerminateReturned")):
        need((value[returned] is None or value[request]) and (not value[request] or value["launchReferenceReturned"]),
             "native-cleanup-original")
    need(not value["forceTerminateRequested"] or value["normalTerminateRequested"], "native-cleanup-order")
    need(not any(value[k] for k in COUNTS) or value["launchRequested"], "native-callback-request")
    need(not value["terminationObserved"] or value["launchReferenceReturned"], "native-termination-original")
    need(value["gateAfterTermination"] == "unobserved" or value["terminationObserved"], "native-postprobe")
    need(value["gateWhileOriginalLive"] == "unobserved" or value["launchReferenceReturned"]
         and value["referenceTerminatedAtObservation"] is False and value["gateBefore"] == "free", "native-live-probe")
    complete = (value["firstFailure"] == "none" and value["launchRequested"] and value["launchReferenceReturned"]
        and not value["launchErrorReported"] and not value["workDeadlineFailed"] and not value["clockUnavailable"]
        and value["finalDeadlineMet"] and value["ancestorCloseReturned"] and value["probeClosesReturned"]
        and all(value[k] == 1 for k in COUNTS) and value["referenceTerminatedAtObservation"] is False
        and value["referenceFinishedLaunching"] is not None and all(value[k] in {"entry", "payload"} for k in IDENTITIES)
        and value["gateBefore"] == "free" and value["gateWhileOriginalLive"] == "busy"
        and value["terminationObserved"] and value["gateAfterTermination"] == "free")
    need(value["observationComplete"] is complete, "native-completeness")
    return value


def direct_outcome(result):
    need(type(result) is subprocess.CompletedProcess and type(result.args) is list and result.args == [ENTRY]
         and type(result.returncode) is int and 0 <= result.returncode <= 255
         and type(result.stdout) is bytes and type(result.stderr) is bytes
         and len(result.stdout) + len(result.stderr) <= LIMIT, "direct-original-result")
    code = result.returncode
    return "returned-zero" if code == 0 else "returned-entry-refusal" if code in ENTRY_REFUSALS else "returned-payload-generic-one" if code == 1 else "returned-other"


def work_path(source, run, attempt, job):
    # Must satisfy the unchanged installer status channel ancestry policy.
    return Path("/Users/runner") / f"mrk-macos-entry-diagnostic-{source}-{run}-{attempt}-{job}"


def load_source(root, relative, name):
    need(name not in sys.modules, "source-module-already-loaded")
    spec = importlib.util.spec_from_file_location(name, root / relative)
    need(spec is not None and spec.loader is not None, "source-module-spec")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Context:
    def __init__(self):
        self.root = Path(__file__).absolute().parents[2]
        self.source = os.environ.get("GITHUB_SHA", "")
        self.run = os.environ.get("GITHUB_RUN_ID", "")
        self.attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
        self.job = os.environ.get("GITHUB_JOB", "")
        self.ui = self.job == "packaged_ui"
        self.ui_helper = None
        phases = {"prepare", "readback", "ui-build", "ui-test"} if self.ui else {"prepare", "readback", "observe"}
        need(len(sys.argv) == 2 and sys.argv[1] in phases, "fixed-phase")
        need(sys.platform == "darwin" and platform.machine() == "arm64" and platform.mac_ver()[0].startswith("26.")
             and threading.current_thread() is threading.main_thread(), "native-host")
        need(re.fullmatch(r"[0-9a-f]{40}", self.source) and all(re.fullmatch(r"[1-9][0-9]{0,19}", x) for x in (self.run, self.attempt))
             and self.job in {"launchservices", "direct_entry", "packaged_ui"}, "run-binding")
        import pwd  # Native admission only; inert DATA parsers remain portable.
        user = pwd.getpwuid(os.getuid())
        need(os.getuid() > 0 and os.getuid() == os.geteuid() == user.pw_uid
             and os.getgid() == os.getegid() == user.pw_gid and user.pw_name == "runner"
             and user.pw_dir == "/Users/runner", "account")
        selected_ref = UI_REF if self.ui else REF
        self.developer = UI_DEVELOPER if self.ui else "/Library/Developer/CommandLineTools"
        if self.ui:
            need(os.stat("/dev/console").st_uid == os.getuid(), "ui-console-account")
        expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
            "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": REPO, "GITHUB_REF": selected_ref,
            "GITHUB_WORKFLOW_REF": f"{REPO}/{WORKFLOW}@{selected_ref}", "GITHUB_WORKFLOW_SHA": self.source,
            "GITHUB_WORKSPACE": str(self.root), "DEVELOPER_DIR": self.developer}
        need(str(self.root) == "/Users/runner/work/mobile-release-kit/mobile-release-kit"
             and all(os.environ.get(k) == v for k, v in expected.items()), "hosted-route")
        self.work = work_path(self.source, self.run, self.attempt, self.job)
        info = self.work.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_gid == os.getgid()
             and stat.S_IMODE(info.st_mode) == 0o700, "work-root")
        self.work_original = full9(info)[:5]
        self.environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/Users/runner", "USER": "runner", "LOGNAME": "runner",
                            "TMPDIR": str(self.work / "tmp") + "/", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TZ": "UTC",
                            "DEVELOPER_DIR": self.developer}
        self.snapshot = self.source_state()
        for name, expected_sha in PINS.items():
            need(expected_sha is not None and name in self.snapshot and self.snapshot[name][1] == expected_sha, "source-pin")
        self.stage = load_source(self.root, STAGER, "mrk_installed_entry_diagnostic_stager")
        # Admit the exact unchanged status channel before package/Installer work.
        # In particular, a sticky or group/world-writable ancestor is refused.
        with self.stage.installer_channel_parent(self.work / "installer-output.status", private=self.work):
            pass
        self.owner = None
        self.inflight = False
        self.last_returned = False
        self.report = {"schemaVersion": 1, "scope": "ordinary-installed-entry-diagnostic-only",
            "diagnosticSource": self.source, "applicationSource": APPLICATION_SOURCE, "runId": self.run, "runAttempt": self.attempt,
            "job": self.job, "platform": platform.mac_ver()[0], "architecture": "arm64", "stage": sys.argv[1],
            "sourceFileCount": len(self.snapshot), "sourceRosterSha256": digest(encoded(self.snapshot, 2 * 1024 * 1024)),
            "artifactId": ARTIFACT_ID, "sourceRun": SOURCE_RUN, "sourceRunAttempt": SOURCE_ATTEMPT,
            "artifactBytes": ARCHIVE_BYTES, "artifactSha256": ARCHIVE_SHA, "commands": [], "native": None,
            "originalCallReturned": False, "applicationCallAttempted": False, "applicationExitStatusAvailable": False, "originalAppExitStatus": None,
            "directEntryOutcome": "not-attempted", "registeredPayloadIdentityObserved": False,
            "diagnosticValid": False, "diagnosticComplete": False, "sourcePrePostMatched": False,
            "normalQuitQualified": False, "fullUIQualified": False, "fullM2Qualified": False, "productReady": False,
            "allWorkerFinality": "not-established", "error": None, "retainedInstallation": True,
            "cleanup": {"compilerOutputsRemoved": False, "unknownStateRetained": False, "error": None}}
        if self.ui:
            self.report.update(scope="packaged-macos-entry-ui-only", harnessSource=self.source,
                ui=None, generatedRunner=None, uiScenarioObserved=False, originalTestReturncode=None,
                cleanExitStatus=None, sameBuildQualified=False)
            # No old native-observer result is manufactured for this selection.
            for name in ("native", "registeredPayloadIdentityObserved", "directEntryOutcome"):
                self.report.pop(name)

    def source_state(self):
        # Fixed read-only Git metadata admission, as in the existing installed
        # workflow. This never invokes a project hook, build, config or command.
        def git(*args):
            value = subprocess.run(["/usr/bin/git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *args],
                cwd=self.root, env={"PATH": "/usr/bin:/bin", "HOME": "/Users/runner", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
                                    "GIT_CONFIG_GLOBAL": "/dev/null"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=15, check=True)
            need(len(value.stdout) <= 2 * 1024 * 1024 and len(value.stderr) <= 4096, "git-output-bound")
            return value.stdout
        need(git("rev-parse", "HEAD") == self.source.encode() + b"\n"
             and read(self.root / ".git/HEAD", 41)[0] == self.source.encode() + b"\n"
             and git("status", "--porcelain=v1", "--untracked-files=all") == b"", "checkout-source")
        rows = git("ls-tree", "-r", "-z", "--full-tree", "HEAD").split(b"\0")
        need(rows[-1] == b"" and 0 < len(rows) - 1 <= 4096, "source-roster")
        result = {}
        for row in rows[:-1]:
            header, raw_name = row.split(b"\t", 1)
            mode, kind, blob = header.split(b" ")
            name = raw_name.decode("utf-8", "strict")
            need(kind == b"blob" and mode in (b"100644", b"100755")
                 and all(p not in ("", ".", "..") for p in name.split("/")) and name not in result,
                 "source-roster-entry")
            body, identity = read(self.root / name, 32 * 1024 * 1024)
            need(hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest() == blob.decode()
                 and bool(identity[2] & 0o111) == (mode == b"100755"), "source-git-correspondence")
            result[name] = [len(body), digest(body), [str(x) for x in identity], mode.decode()]
        return result

    def check(self):
        need(full9(self.work.lstat())[:5] == self.work_original and self.source_state() == self.snapshot, "original-source-changed")

    def selected(self):
        value = preview(read(self.work / "PREVIEW.json", 32768)[0])
        package = read(self.work / "MobileReleaseKit.pkg", 64 * 1024 * 1024)[0]
        need(len(package) == value["packageSize"] and digest(package) == value["packageSha256"], "prepared-package-changed")
        need(digest(read(self.work / "input/install-inventory.json", 1024 * 1024)[0]) == value["installerInventorySha256"],
             "prepared-inventory-changed")
        self.report.update(packageSha256=value["packageSha256"], packageBytes=value["packageSize"],
            inventorySha256=value["installerInventorySha256"], runtimeManifestSha256=value["runtimeManifestSha256"])
        return value

    def observation_args(self, value):
        return argparse.Namespace(input=self.work / "input", expected_source=APPLICATION_SOURCE,
            expected_inventory=value["installerInventorySha256"], expected_manifest=value["runtimeManifestSha256"],
            installer_status=self.work / "installer-output.status", fixture=False)

    def prepare(self):
        artifact = document(read(self.work / "artifact.json", LIMIT)[0])
        source_run = document(read(self.work / "source-run.json", 256 * 1024)[0], 256 * 1024)
        need(type(artifact.get("id")) is int and str(artifact["id"]) == ARTIFACT_ID
             and artifact.get("expired") is False and type(artifact.get("size_in_bytes")) is int
             and artifact["size_in_bytes"] == ARCHIVE_BYTES and artifact.get("digest") == "sha256:" + ARCHIVE_SHA,
             "artifact-metadata")
        original = artifact.get("workflow_run")
        need(type(original) is dict and type(original.get("id")) is int and str(original["id"]) == SOURCE_RUN
             and original.get("head_sha") == APPLICATION_SOURCE and original.get("head_branch") == "verify/desktop-macos-preview",
             "artifact-run-binding")
        need(type(source_run.get("id")) is int and str(source_run["id"]) == SOURCE_RUN
             and source_run.get("run_attempt") == 1 and type(source_run.get("run_attempt")) is int
             and source_run.get("head_sha") == APPLICATION_SOURCE and source_run.get("head_branch") == "verify/desktop-macos-preview"
             and source_run.get("event") == "push" and source_run.get("path") == ".github/workflows/desktop-macos-installed.yml"
             and source_run.get("status") == "completed" and source_run.get("conclusion") == "failure"
             and source_run.get("repository", {}).get("full_name") == REPO
             and source_run.get("head_repository", {}).get("full_name") == REPO, "original-run-metadata")
        members, value = archive_members(read(self.work / "original-preview.zip", ARCHIVE_BYTES)[0])
        inventory, facts = package_inventory(self.stage, members["MobileReleaseKit.pkg"], value,
                                             read(self.root / "desktop/macos-installed-inputs/postinstall", 8192)[0])
        try:
            INSTALL_ROOT.lstat()
        except FileNotFoundError:
            pass
        else:
            raise Refused("installation-collision")
        self.stage.installer_result_absent_command(argparse.Namespace(expected_source=APPLICATION_SOURCE,
            expected_inventory=value["installerInventorySha256"], expected_manifest=value["runtimeManifestSha256"], fixture=False))
        self.check()
        (self.work / "input").mkdir(mode=0o700)
        write_new(self.work / "input/install-inventory.json", inventory, 0o444)
        write_new(self.work / "PREVIEW.json", members["PREVIEW.json"], 0o444)
        write_new(self.work / "MobileReleaseKit.pkg", members["MobileReleaseKit.pkg"], 0o444)
        self.selected()
        self.report.update(packageData=facts, executablePayloadsExtracted=False, freshDestinationAbsent=True,
                           diagnosticValid=True, diagnosticComplete=True)

    def readback(self):
        selected = self.selected()
        result = self.stage.observation_command(self.observation_args(selected))
        need(result.get("applicationLaunched") is False and result.get("guiSaveQualified") is False, "readback-scope")
        self.report.update(readbackSha256=digest(encoded(result)), readbackFileCount=result["nonrootReadbackFileCount"],
                           freshInstallerOriginalZero=True, diagnosticValid=True, diagnosticComplete=True)

    def call(self, role, argv, timeout):
        self.check()
        self.report["stage"] = role
        self.inflight, self.last_returned = True, False
        if role in {"one-direct-entry", "one-launchservices-observer", "one-admitted-ui-test"}:
            self.report["applicationCallAttempted"] = True
        result = self.owner.run_owned(argv, environ=self.environment, cwd=self.work,
                                      timeout=timeout, capture=True, text=False, output_limit=LIMIT)
        self.last_returned = True
        need(type(result) is subprocess.CompletedProcess and type(result.args) is list and result.args == argv
             and type(result.returncode) is int and 0 <= result.returncode <= 255
             and type(result.stdout) is bytes and type(result.stderr) is bytes
             and len(result.stdout) + len(result.stderr) <= LIMIT, "owner-original-result")
        self.inflight = False
        self.report["commands"].append({"role": role, "originalCallReturned": True, "returncode": result.returncode,
            "stdoutBytes": len(result.stdout), "stdoutSha256": digest(result.stdout),
            "stderrBytes": len(result.stderr), "stderrSha256": digest(result.stderr)})
        self.check()
        return result

    def zero(self, role, argv, timeout=30):
        result = self.call(role, argv, timeout)
        if result.returncode and role.startswith("compile-"):
            # Fixed compiler source, no project/account data in this job. Still
            # preserve only bounded diagnostic categories, never raw paths.
            self.report["compilerErrors"] = [re.sub(r"/[^ \t\"\']+", "<path>", line.split("error:", 1)[1])[:300]
                for line in result.stderr.decode("utf-8", "replace").splitlines() if "error:" in line][:8]
        need(result.returncode == 0, role + "-status")
        return result

    def ui_tools(self):
        need(self.ui and self.developer == UI_DEVELOPER, "fixed-ui-profile")
        loader = load_source(self.root, LOADER, "mrk_packaged_ui_owner_loader")
        self.owner = loader.load_owner(self.root)
        self.ui_helper = load_source(self.root, UI_HELPER, "mrk_packaged_ui_runner_admission")

    def ui_prior(self, phase):
        need(phase in {"readback", "ui-build"}, "fixed-ui-prior")
        prior = document(read(self.work / (phase + ".json"), LIMIT)[0])
        need(prior.get("scope") == "packaged-macos-entry-ui-only"
             and prior.get("diagnosticSource") == self.source and prior.get("harnessSource") == self.source
             and prior.get("applicationSource") == APPLICATION_SOURCE and prior.get("job") == self.job
             and prior.get("runId") == self.run and prior.get("runAttempt") == self.attempt
             and prior.get("sourceRosterSha256") == self.report["sourceRosterSha256"]
             and prior.get("diagnosticComplete") is True and prior.get("sourcePrePostMatched") is True
             and prior.get("error") is None, "original-ui-prior-result")
        return prior

    def ui_file_budget(self, phase):
        import resource  # Native UI phase only, not portable DATA import.
        expected = 32 * 1024**3 if phase == "build" else 1024**3
        actual = resource.getrlimit(resource.RLIMIT_FSIZE)
        need(actual == (expected, expected), "ui-file-budget")
        self.report["fileBudget"] = {"phase": phase, "expectedBytes": expected, "softBytes": actual[0],
            "hardBytes": actual[1], "admitted": True, "serviceLimitsObserved": False}

    def ui_build(self):
        self.ui_file_budget("build")
        prior = self.ui_prior("readback")
        need(prior.get("freshInstallerOriginalZero") is True, "original-ui-installer-zero")
        selected = self.selected()
        need(selected["packageSize"] == PACKAGE_BYTES and selected["packageSha256"] == PACKAGE_SHA,
             "fixed-reused-ui-package")
        self.readback()
        self.report.update(diagnosticValid=False, diagnosticComplete=False)
        self.ui_tools()
        (self.work / "tmp").mkdir(mode=0o700)
        ui = self.work / "normal-ui"; ui.mkdir(mode=0o700)
        write_new(self.work / "ui-build-attempted", b"packaged_ui\n", 0o400)
        commands = {
            "xcode": ["/usr/bin/xcodebuild", "-version"],
            "sdkPath": ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"],
            "sdkVersion": ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version"],
            "sdkBuild": ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-build-version"],
        }
        toolchain = {}
        self.report["toolchain"] = {}
        with SelectedUIToolchain(self.ui_helper, self.report) as authority:
            for role, command in commands.items():
                original = self.zero("ui-toolchain-" + role, command, 15)
                need(0 < len(original.stdout) <= 4096, "ui-toolchain-bound")
                toolchain[role] = original.stdout.decode("ascii", "strict").strip()
                self.report["toolchain"].update(ui_public_toolchain({role: toolchain[role]}))
            authority.state["check"] = "toolchain-values"
            need(set(self.report["toolchain"]) == set(commands)
                 and re.fullmatch(r"Xcode 26(?:\.[0-9]+)*\nBuild version [0-9A-Za-z]+", toolchain["xcode"])
                 and re.fullmatch(r"26(?:\.[0-9]+)*", toolchain["sdkVersion"])
                 and re.fullmatch(r"[0-9A-Za-z]+", toolchain["sdkBuild"]), "ui-fixed-toolchain")
            authority.admit_sdk(toolchain["sdkPath"], toolchain["sdkVersion"])
        # Same selected originals were rechecked and all consuming closes returned.
        self.zero("build-ui-runner", ["/usr/bin/xcodebuild", "build-for-testing", "-quiet",
            "-project", str(self.root / self.ui_helper.PROJECT), "-scheme", "MRKNormalAppUI",
            "-configuration", "Debug", "-destination", "platform=macOS,arch=arm64", "-destination-timeout", "15",
            "-derivedDataPath", str(ui / "DerivedData"), "-jobs", "2",
            "-disableAutomaticPackageResolution", "COMPILER_INDEX_STORE_ENABLE=NO"], 240)
        self.report.update(diagnosticValid=True, diagnosticComplete=True, buildOriginalZero=True,
                           applicationRebuilt=False)

    def ui_test(self):
        self.ui_file_budget("test")
        prior = self.ui_prior("ui-build")
        need(prior.get("buildOriginalZero") is True and prior.get("applicationRebuilt") is False,
             "original-ui-runner-build")
        selected = self.selected()
        need(selected["packageSize"] == PACKAGE_BYTES and selected["packageSha256"] == PACKAGE_SHA,
             "fixed-reused-ui-package")
        self.readback()
        self.report.update(diagnosticValid=False, diagnosticComplete=False, toolchain=prior["toolchain"],
                           buildReportSha256=digest(read(self.work / "ui-build.json", LIMIT)[0]))
        self.ui_tools()
        write_new(self.work / "ui-test-attempted", b"packaged_ui\n", 0o400)
        self.environment.update({
            "TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB": "github-hosted-macos26-arm64",
            "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE": APPLICATION_SOURCE,
            "TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE": self.source,
            "TEST_RUNNER_MRK_NORMAL_UI_ARTIFACT_ID": ARTIFACT_ID,
            "TEST_RUNNER_MRK_NORMAL_UI_ARCHIVE_BYTES": str(ARCHIVE_BYTES),
            "TEST_RUNNER_MRK_NORMAL_UI_ARCHIVE_SHA256": ARCHIVE_SHA,
            "TEST_RUNNER_MRK_NORMAL_UI_PACKAGE_BYTES": str(PACKAGE_BYTES),
            "TEST_RUNNER_MRK_NORMAL_UI_PACKAGE_SHA256": PACKAGE_SHA,
        })
        ui = self.work / "normal-ui"
        result_path = ui / "test.xcresult"
        original, runner = self.ui_helper.run_admitted_test(self.call, ui / "DerivedData",
            result_path, (self.ui_helper.PACKAGED_METHOD,), 60, 180)
        self.report.update(generatedRunner=runner, originalTestReturncode=original.returncode,
                           originalCallReturned=True)
        if original.returncode != 0:
            diagnostics = ui_failure_unavailable()
            try:
                projected = ui_failure_diagnostics(original.stdout, original.stderr)
                encoded(projected, UI_FAILURE_LIMIT)
                diagnostics = projected
            except Exception:
                pass  # The original nonzero refusal wins, without exception text.
            self.report["uiFailureDiagnostics"] = diagnostics
        need(original.returncode == 0, "original-ui-test-nonzero")
        summary = self.zero("original-ui-summary", ["/usr/bin/xcrun", "xcresulttool", "get", "test-results",
            "summary", "--path", str(result_path), "--compact"], 15)
        tests = self.zero("original-ui-tests", ["/usr/bin/xcrun", "xcresulttool", "get", "test-results",
            "tests", "--path", str(result_path), "--compact"], 15)
        accepted = self.ui_helper.packaged_ui_result(original.stdout, summary.stdout, tests.stdout)
        accepted["originalXcodebuildReturncode"] = original.returncode
        observed = self.stage.observation_command(self.observation_args(selected))
        self.report.update(ui=accepted, uiScenarioObserved=True, diagnosticValid=True, diagnosticComplete=True,
            postObservationReadbackSha256=digest(encoded(observed)))
        # Installation, DerivedData, xcresult and unknown app/worker state stay
        # in this exclusive disposable job. No direct-entry rerun or cleanup probe.

    def observe(self):
        selected = self.selected()
        prior = document(read(self.work / "readback.json", LIMIT)[0])
        need(prior.get("diagnosticSource") == self.source and prior.get("applicationSource") == APPLICATION_SOURCE
             and prior.get("job") == self.job and prior.get("runId") == self.run and prior.get("runAttempt") == self.attempt
             and prior.get("freshInstallerOriginalZero") is True and prior.get("diagnosticComplete") is True
             and prior.get("sourcePrePostMatched") is True and prior.get("error") is None, "original-readback-result")
        self.readback()  # Recheck actual installed bytes immediately before native work.
        self.report.update(diagnosticValid=False, diagnosticComplete=False)
        loader = load_source(self.root, LOADER, "mrk_installed_entry_diagnostic_owner_loader")
        self.owner = loader.load_owner(self.root)
        (self.work / "tmp").mkdir(mode=0o700)
        if self.job == "direct_entry":
            write_new(self.work / "launch-attempted", b"direct_entry\n", 0o400)
            self.report["stage"] = "one-direct-entry"
            try:
                result = self.call("one-direct-entry", [ENTRY], 15)
            except BaseException:
                self.report["directEntryOutcome"] = "owner-exception"
                raise
            self.report.update(directEntryOutcome=direct_outcome(result), originalCallReturned=True,
                applicationExitStatusAvailable=True, originalAppExitStatus=result.returncode,
                diagnosticValid=True, diagnosticComplete=True)
            need(result.returncode == 0, "direct-entry-nonzero")
        else:
            build = self.work / "build"; build.mkdir(mode=0o700)
            header = (f'#define MRK_DIAGNOSTIC_SOURCE "{self.source}"\n'
                      f'#define MRK_APPLICATION_SOURCE "{APPLICATION_SOURCE}"\n').encode()
            write_new(build / "diagnostic_source.h", header, 0o400)
            compiler = ["/usr/bin/xcrun", "--sdk", "macosx", "clang", "-arch", "arm64", "-mmacosx-version-min=26.0"]
            native = self.root / "desktop/native/macos-installed-native/src/native.m"
            gate = self.root / "desktop/native/macos-installed-entry"
            self.zero("compile-metadata", compiler + ["-DMRK_ENTRY_METADATA_ONLY=1", "-c", str(native), "-o", str(build / "metadata.o")], 60)
            self.zero("compile-gate", compiler + ["-c", str(gate / "gate.c"), "-o", str(build / "gate.o")], 60)
            observer = build / "observe"
            self.zero("compile-observer", compiler + ["-fobjc-arc", "-fblocks", "-I", str(gate), "-I", str(build),
                str(self.root / NATIVE), str(build / "metadata.o"), str(build / "gate.o"),
                "-framework", "AppKit", "-framework", "Foundation", "-o", str(observer)], 60)
            self.zero("sign-observer", ["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", "--options", "runtime", str(observer)])
            self.zero("verify-observer", ["/usr/bin/codesign", "--verify", "--strict", str(observer)])
            entitlements = self.zero("observer-entitlements", ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(observer)])
            need(not entitlements.stdout or plistlib.loads(entitlements.stdout) == {}, "observer-entitlements")
            observer_bytes, observer_original = read(observer, 8 * 1024 * 1024)
            self.report.update(observerBytes=len(observer_bytes), observerSha256=digest(observer_bytes), observerSandboxEntitlement=False,
                               generatedHeaderSha256=digest(header))
            write_new(self.work / "launch-attempted", b"launchservices\n", 0o400)
            result = self.call("one-launchservices-observer", [str(observer)], 60)
            native_result_value = native_result(result.stdout, self.source)
            need(read(observer, 8 * 1024 * 1024)[1] == observer_original, "observer-original-changed")
            self.report.update(native=native_result_value, originalCallReturned=True, diagnosticValid=True,
                diagnosticComplete=native_result_value["observationComplete"] and result.returncode == 0,
                registeredPayloadIdentityObserved=all(native_result_value[k] == "payload" for k in IDENTITIES))
            need(result.returncode == 0 and native_result_value["observationComplete"], "launchservices-observation-incomplete")
        # Fresh successful Installer0 stays the independent readback basis;
        # this checked correspondence does not claim the app was not launched.
        observed = self.stage.observation_command(self.observation_args(selected))
        self.report["postObservationReadbackSha256"] = digest(encoded(observed))
        self.check()

    def failure(self, error):
        known_ui = self.ui_helper is not None and type(error) is self.ui_helper.Refused
        label = str(error) if type(error) is Refused or type(error) is self.stage.Refused or known_ui else "interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "diagnostic-or-owner-error"
        self.report["error"] = label if re.fullmatch(r"[a-z][a-z0-9-]{0,95}", label) else "diagnostic-or-owner-error"
        self.report["originalCallReturned"] = self.last_returned
        if self.owner is not None and isinstance(error, (self.owner.ProcessError, self.owner.ProcessInterrupted)):
            self.report["ownerFailure"] = {name: value if type(value := getattr(error, attr, None)) is bool else None
                for name, attr in (("dispatched", "dispatched"), ("contained", "contained"), ("cleanupComplete", "cleanup_complete"))}
        self.report["cleanup"]["unknownStateRetained"] = self.inflight or not self.report["diagnosticComplete"]

    def cleanup(self):
        # Only no-longer-needed closed compiler products. Installation and app
        # temp remain even after NSRunningApplication termination was observed.
        if self.inflight:
            self.report["cleanup"]["unknownStateRetained"] = True
            return
        build = self.work / "build"
        try:
            info = build.lstat()
        except FileNotFoundError:
            return
        need(full9(self.work.lstat())[:5] == self.work_original and stat.S_ISDIR(info.st_mode)
             and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "cleanup-root")
        if self.report["stage"] == "one-launchservices-observer" and not self.report["diagnosticComplete"]:
            self.report["cleanup"]["unknownStateRetained"] = True
            return
        names = {"diagnostic_source.h", "metadata.o", "gate.o", "observe"}
        need({child.name for child in build.iterdir()} <= names, "cleanup-roster")
        for child in build.iterdir():
            data, identity = read(child, 8 * 1024 * 1024)
            need(identity[3] == os.getuid() and identity[4] == os.getgid(), "cleanup-owner")
        need(shutil.rmtree.avoids_symlink_attacks, "cleanup-api")
        fd = os.open(self.work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            need(full9(os.fstat(fd))[:5] == self.work_original, "cleanup-original")
            shutil.rmtree("build", dir_fd=fd)
        finally:
            os.close(fd)
        self.report["cleanup"]["compilerOutputsRemoved"] = True


def main():
    context = None
    success = False
    try:
        os.umask(0o077)
        context = Context()
        getattr(context, sys.argv[1].replace("-", "_"))()
        context.check()
        context.report["sourcePrePostMatched"] = True
        success = True
    except BaseException as error:
        if context is None:
            # No admitted directory/reference exists; stdout is an explicitly
            # limited admission failure, not an output/finality receipt.
            print(json.dumps({"schemaVersion": 1, "scope": "entry-diagnostic-admission-failure", "productReady": False,
                              "error": str(error) if type(error) is Refused else "admission-error"}, sort_keys=True))
            return 1
        context.failure(error)
    try:
        if sys.argv[1] == "observe":
            context.cleanup()
        context.check()
        context.report["sourcePrePostMatched"] = True
    except BaseException:
        context.report["cleanup"]["error"] = "postcheck-or-cleanup-refused"
        context.report["sourcePrePostMatched"] = False
        context.report["diagnosticComplete"] = False
        if context.report["error"] is None:
            context.report["error"] = "postcheck-or-cleanup-refused"
        success = False
    try:
        write_new(context.work / (sys.argv[1] + ".json"), encoded(context.report))
    except BaseException:
        return 1
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
