#!/usr/bin/env python3
"""Fixed generated Mac UI-runner admission; no application launch or repair here.

Import is inert. The diagnostic uses its existing original-command owner; the
normal workflow CLI admits fixed build/summary phases and eight exact test selections.
Only XCTest/NSWorkspace in the reviewed Swift source may request the outer app.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import plistlib
import posixpath
import re
import stat
import subprocess
import sys
import time

# Loaded before any fixture worker starts; no process-global limits are changed.
if sys.platform == "darwin":
    import resource as _removal_resource
else:
    _removal_resource = None

DEVELOPER = "/Applications/Xcode.app/Contents/Developer"
ARM_TARGET = "aarch64-apple-darwin"
INTEL_TARGET = "x86_64-apple-darwin"
PROJECT = "desktop/native/macos-normal-ui/MRKNormalAppUI.xcodeproj"
LOADER = "desktop/tools/macos_aqua_qualification.py"
LOADER_SHA = "7b53c155874177a413fd1df382543ba50540f769b6b0fbfddace002e7f257016"
LOADER_MODULE = "mrk_normal_ui_owner_loader"
TARGET = "MRKNormalAppUITests"
CLASS = TARGET + "/NormalAppUITests/"
PACKAGED_METHOD = CLASS + "testPackagedEntryLaunchCancelAndQuit"
RUNNER = "Debug/MRKNormalAppUITests-Runner.app"
RUNNER_EXECUTABLE = RUNNER + "/Contents/MacOS/MRKNormalAppUITests-Runner"
TEST_BUNDLE = RUNNER + "/Contents/PlugIns/MRKNormalAppUITests.xctest"
TEST_EXECUTABLE = TEST_BUNDLE + "/Contents/MacOS/MRKNormalAppUITests"
RUNNER_INFO = RUNNER + "/Contents/Info.plist"
TEST_INFO = TEST_BUNDLE + "/Contents/Info.plist"
NORMAL_SELECTIONS = {
    "test.xcresult": (("testLaunchCancelAndQuit",), 60, 180),
    "project-test.xcresult": (("testSyntheticProjectLocalEditsAndImages",
                              "testSyntheticProjectPathFields"), 300, 720),
    "persistence-test.xcresult": (("testSyntheticPersistentCredentials",), 300, 420),
    "diagnostics-test.xcresult": (("testSyntheticProjectBuildToolDiagnostics",), 300, 420),
    "saved-checks-test.xcresult": (("testSyntheticProjectSavedOfflineChecks",
                                  "testSyntheticProjectEmptyBuildInputInspection"), 300, 720),
    "workflow-refusal-test.xcresult": (("testSyntheticProjectManagedWorkflowRefusal",), 300, 420),
    "release-evidence-test.xcresult": (("testSyntheticProjectSavedReleaseEvidence",), 300, 420),
    "saved-version-recovery-test.xcresult": (("testSyntheticProjectSavedVersionRecovery",), 300, 420),
}
ORIGINAL_MARKER = ("MRK_MACOS_UI_ORIGINAL=outerRequest=1;completion=1;body=1;handoff=1;"
    "payloadIdentity=1;originalTerminated=1;gateFree=1;gateClosed=1;failureCleanup=0;caseDeadlineMet=1")
ENTRY_MARKER = ("MRK_MACOS_ENTRY_UI=ordinary-entry-payload-picker-quit-and-gate-exclusion-observed;"
    "directPayloadPreMain=unqualified;allWorkerFinality=unavailable;maintenance=unavailable")
UI_MARKER = ("MRK_MACOS_NORMAL_UI=launch-render-cancel-navigation-quit-observed;"
    "cleanExitStatus=unavailable;allWorkerFinality=unavailable")


class Refused(Exception):
    """Only closed public labels escape native main."""


def need(value, reason):
    if not value:
        raise Refused(reason)


def normal_target_data(target=ARM_TARGET):
    """Closed requested target DATA; native context must independently match."""
    need(type(target) is str and target in (ARM_TARGET, INTEL_TARGET), "normal-fixed-target")
    return (("arm64", "github-hosted-macos26-arm64") if target == ARM_TARGET else
            ("x86_64", "github-hosted-macos26-x86_64"))


def sha(body):
    return hashlib.sha256(body).hexdigest()


def full9(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def decimal(values):
    return [str(value) for value in values]


class UniqueDict(dict):
    def __setitem__(self, key, value):
        need(key not in self, "duplicate-plist-key")
        super().__setitem__(key, value)


def plist(body):
    need(type(body) is bytes and 0 < len(body) <= 1024 * 1024, "plist-bound")
    try:
        value = plistlib.loads(body, dict_type=UniqueDict)
    except Refused:
        raise
    except Exception:
        raise Refused("malformed-plist") from None
    need(isinstance(value, dict), "plist-object")
    return value


def sandbox_entitlement(body):
    # Empty/unknown codesign output is NOT evidence of an absent entitlement.
    value = plist(body)
    if "com.apple.security.app-sandbox" not in value:
        return "absent"
    sandbox = value["com.apple.security.app-sandbox"]
    need(type(sandbox) is bool and sandbox is False, "sandboxed-or-unknown-runner")
    return "false"


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def document(body):
    need(type(body) is bytes and 0 < len(body) <= 65536, "result-json-bound")
    value = json.loads(body.decode("utf-8", "strict"), object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(Refused("result-json-number")))
    need(type(value) is dict, "result-json-object")
    return value


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def target_from_xctestrun(body, products):
    value = plist(body)
    metadata = value.get("__xctestrun_metadata__")
    need(isinstance(metadata, dict) and type(metadata.get("FormatVersion")) is int, "xctestrun-metadata")
    version = metadata["FormatVersion"]
    if version == 1:
        need(set(value) == {"__xctestrun_metadata__", TARGET}, "xctestrun-one-target")
        target = value[TARGET]
    elif version == 2:
        configurations = value.get("TestConfigurations")
        need(type(configurations) is list and len(configurations) == 1, "xctestrun-one-configuration")
        configuration = configurations[0]
        need(isinstance(configuration, dict) and configuration.get("IsEnabled", True) is True,
             "xctestrun-enabled-configuration")
        targets = configuration.get("TestTargets")
        need(type(targets) is list and len(targets) == 1, "xctestrun-one-target")
        target = targets[0]
    else:
        raise Refused("xctestrun-format")
    need(isinstance(target, dict) and target.get("BlueprintName", TARGET) == TARGET
         and target.get("IsUITestBundle") is True, "xctestrun-fixed-ui-target")
    host = str(products / RUNNER)
    bundle = str(products / TEST_BUNDLE)
    need(target.get("TestHostPath") in {host, "__TESTROOT__/" + RUNNER}
         and target.get("TestBundlePath") in {bundle, "__TESTROOT__/" + TEST_BUNDLE,
                                              "__TESTHOST__/Contents/PlugIns/MRKNormalAppUITests.xctest"},
         "xctestrun-exact-runner-products")
    need(target.get("TestHostBundleIdentifier") == "dev.mobile-release-kit.normal-ui-tests.xctrunner"
         and target.get("UITargetAppPath", "") == "" and target.get("UITargetAppBundleIdentifier", "") == "",
         "xctestrun-no-application-target")
    return target


def open_directory(path):
    path = Path(path)
    need(path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts[1:]), "absolute-directory")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            old, fd = fd, next_fd
            os.close(old)
        result, fd = fd, None
        return result
    finally:
        if fd is not None:
            os.close(fd)


def original_body(fd, limit, collect=False):
    before = full9(os.fstat(fd))
    need(stat.S_ISREG(before[2]) and before[5] == 1 and 0 <= before[6] <= limit, "ordinary-file-bound")
    digest = hashlib.sha256()
    offset, chunks = 0, []
    while True:
        block = os.pread(fd, min(65536, limit + 1 - offset), offset)
        if not block:
            break
        offset += len(block)
        need(offset <= limit, "ordinary-file-read-bound")
        digest.update(block)
        if collect:
            chunks.append(block)
    need(offset == before[6] and full9(os.fstat(fd)) == before, "original-file-changed")
    return (b"".join(chunks) if collect else None), before, digest.hexdigest()


class RunnerProducts:
    """Exactly the fresh Build/Products roster plus retained critical originals."""
    def __init__(self, derived):
        self.products = Path(derived) / "Build/Products"
        self.fd = None
        self.held = {}
        self.roster = None
        self.closed = False

    def __enter__(self):
        try:
            self.fd = open_directory(self.products)
            names = []
            with os.scandir(self.fd) as entries:
                for entry in entries:
                    names.append(entry.name)
                    need(len(names) <= 32, "build-products-root-bound")
            manifests = [name for name in names if re.fullmatch(r"MRKNormalAppUI_macosx[0-9A-Za-z_.-]+\.xctestrun", name)]
            need(len(manifests) == 1 and set(names) == {"Debug", manifests[0]}, "build-products-exact-roster")
            self.manifest = manifests[0]
            self.keep = {self.manifest, RUNNER_EXECUTABLE, TEST_EXECUTABLE, RUNNER_INFO, TEST_INFO}
            self.roster = self.scan(retain=True)
            need(self.keep <= set(self.held), "runner-critical-original-missing")
            for executable in (RUNNER_EXECUTABLE, TEST_EXECUTABLE):
                info = os.fstat(self.held[executable])
                need(info.st_mode & 0o111 and info.st_size > 0, "runner-original-executable")
            target_from_xctestrun(self.body(self.manifest), self.products)
            for relative, identifier, executable in (
                (RUNNER_INFO, "dev.mobile-release-kit.normal-ui-tests.xctrunner", "MRKNormalAppUITests-Runner"),
                (TEST_INFO, "dev.mobile-release-kit.normal-ui-tests", "MRKNormalAppUITests")):
                info = plist(self.body(relative))
                need(info.get("CFBundleIdentifier") == identifier and info.get("CFBundleExecutable") == executable,
                     "runner-info-correspondence")
            return self
        except BaseException:
            try:
                self.close()
            except BaseException:
                pass  # Keep the original refusal; all acquired closes were consumed.
            raise

    def scan(self, retain=False):
        rows, links = {}, {}
        total = 0
        def walk(fd, prefix, depth):
            nonlocal total
            need(depth <= 24, "runner-depth-bound")
            before = full9(os.fstat(fd))
            need(stat.S_ISDIR(before[2]) and before[3] == os.getuid() and before[4] == os.getgid()
                 and not before[2] & 0o022, "runner-directory-policy")
            need(len(rows) < 4096, "runner-global-roster-bound")
            rows[prefix] = ["directory", decimal(before)]
            names = []
            with os.scandir(fd) as entries:
                for entry in entries:
                    names.append(entry.name)
                    need(len(names) <= 2048 and len(rows) + len(names) <= 4096, "runner-roster-bound")
            for name in sorted(names):
                need(name not in ("", ".", "..") and "/" not in name, "runner-component")
                relative = prefix + "/" + name if prefix else name
                need(len(rows) < 4096 and len(relative.encode("utf-8")) <= 1024, "runner-global-path-bound")
                named = full9(os.stat(name, dir_fd=fd, follow_symlinks=False))
                need(named[3] == os.getuid() and named[4] == os.getgid()
                     and (stat.S_ISLNK(named[2]) or not named[2] & 0o022),
                     "runner-entry-owner-mode")
                if stat.S_ISDIR(named[2]):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        need(full9(os.fstat(child)) == named, "runner-directory-original")
                        walk(child, relative, depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(named[2]):
                    child = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        _, identity, digest = original_body(child, 256 * 1024 * 1024)
                        need(identity == named, "runner-file-original")
                        total += identity[6]
                        need(total <= 1024 * 1024 * 1024, "runner-total-byte-bound")
                        rows[relative] = ["file", decimal(identity), digest]
                        if retain and relative in self.keep:
                            self.held[relative], child = child, None
                    finally:
                        if child is not None:
                            os.close(child)
                elif stat.S_ISLNK(named[2]):
                    target = os.readlink(name, dir_fd=fd)
                    need(0 < len(target.encode()) <= 1024 and not target.startswith("/"), "runner-internal-link")
                    links[relative] = target
                    rows[relative] = ["link", decimal(named), target]
                else:
                    raise Refused("runner-special-file")
                need(full9(os.stat(name, dir_fd=fd, follow_symlinks=False)) == named, "runner-named-changed")
            need(full9(os.fstat(fd)) == before, "runner-directory-changed")
        walk(self.fd, "", 0)
        # Framework version symlinks may be internal, never absolute/external.
        for name, target in links.items():
            pending = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
            for _ in range(32):
                need(pending != ".." and not pending.startswith("../") and not pending.startswith("/"), "runner-link-escape")
                parts = pending.split("/")
                found = next((i for i in range(len(parts)) if "/".join(parts[:i + 1]) in links), None)
                if found is None:
                    need(pending in rows, "runner-link-target-missing")
                    break
                prefix = "/".join(parts[:found + 1])
                pending = posixpath.normpath(posixpath.join(posixpath.dirname(prefix), links[prefix], *parts[found + 1:]))
            else:
                raise Refused("runner-link-cycle")
        need(full9(os.stat(self.products, follow_symlinks=False)) == full9(os.fstat(self.fd)), "products-path-changed")
        return rows

    def body(self, relative):
        value, identity, digest = original_body(self.held[relative], 1024 * 1024, collect=True)
        need(self.roster[relative] == ["file", decimal(identity), digest], "critical-original-changed")
        return value

    def check(self):
        need(not self.closed and self.scan() == self.roster, "runner-products-pre-post")
        for relative, fd in self.held.items():
            _, identity, digest = original_body(fd, 256 * 1024 * 1024)
            need(self.roster[relative] == ["file", decimal(identity), digest], "retained-critical-changed")

    def admit(self, call):
        self.check()
        path = str(self.products / RUNNER)
        verify = call("verify-generated-runner", ["/usr/bin/codesign", "--verify", "--strict", path], 30)
        need(verify.returncode == 0, "generated-runner-signature")
        result = call("generated-runner-entitlements", ["/usr/bin/codesign", "-d", "--entitlements", ":-", path], 30)
        need(result.returncode == 0, "generated-runner-entitlement-inspection")
        sandbox = sandbox_entitlement(result.stdout)
        self.check()
        return {"schemaVersion": 1, "scope": "actual-generated-xctrunner-admission-only",
            "runnerPath": path, "xctestrunPath": str(self.products / self.manifest),
            "runnerExecutable": self.roster[RUNNER_EXECUTABLE], "testExecutable": self.roster[TEST_EXECUTABLE],
            "xctestrun": self.roster[self.manifest], "productEntryCount": len(self.roster),
            "productRosterSha256": sha(encoded(self.roster)), "entitlementsSha256": sha(result.stdout),
            "appSandboxEntitlement": sandbox, "strictCodesignOriginalZero": True,
            "reSignedOrRepaired": False, "originalProductsPrePostMatched": False, "originalClosesCompleted": False}

    def close(self):
        if self.closed:
            return
        self.closed = True
        failure = None
        for relative in tuple(self.held):
            fd = self.held.pop(relative)  # Consume BEFORE close, never retry.
            try:
                os.close(fd)
            except BaseException as error:
                if failure is None:
                    failure = error
        if self.fd is not None:
            fd, self.fd = self.fd, None
            try:
                os.close(fd)
            except BaseException as error:
                if failure is None:
                    failure = error
        if failure is not None:
            raise failure

    def __exit__(self, kind, value, traceback):
        try:
            self.close()
        except BaseException:
            if kind is None:
                raise
        return False


def xcode_test_arguments(manifest, result, methods, allowance, *, target=ARM_TARGET, engineering=False, output_data=False, android_positive=False, ios_unsigned=False, removal_case=None):
    machine, _ = normal_target_data(target)
    need(tuple(methods) != (PACKAGED_METHOD,) or target == ARM_TARGET, "fixed-packaged-test-target")
    need(type(engineering) is bool and (not engineering or (target == ARM_TARGET and tuple(methods) == (ENGINEERING_METHOD,) and allowance == 60)), "engineering-fixed-test-selection")
    need(type(output_data) is bool and (not output_data or (not engineering and target == ARM_TARGET
         and tuple(methods) == (OUTPUT_DATA_METHOD,) and allowance == 60)), "output-data-fixed-test-selection")
    need(type(android_positive) is bool and (not android_positive or (not engineering and not output_data
         and target == ARM_TARGET and tuple(methods) == (CLASS + ANDROID_METHOD,) and allowance == 900
         and Path(result).name == ANDROID_RESULT)), "android-signed-fixed-test-selection")
    need(type(ios_unsigned) is bool and (not ios_unsigned or (not engineering and not output_data and not android_positive
         and tuple(methods) == (CLASS + IOS_UNSIGNED_METHOD,) and allowance == 900 and Path(result).name == IOS_UNSIGNED_RESULT)),
         "ios-unsigned-fixed-test-selection")
    if removal_case is not None:
        selected, basename = removal_selection(removal_case)
        need(not any((engineering, output_data, android_positive, ios_unsigned)) and target == ARM_TARGET
             and tuple(methods) == (selected,) and allowance == 300 and Path(result).name == basename,
             "removal-fixed-test-selection")
    need(removal_case is not None or ios_unsigned or android_positive or output_data or engineering or tuple(methods) == (PACKAGED_METHOD,) or
         any(tuple(methods) == tuple(CLASS + method for method in selection[0])
             and allowance == selection[1] for selection in NORMAL_SELECTIONS.values()),
         "fixed-test-selection")
    need(((android_positive or ios_unsigned) and allowance == 900 or not (android_positive or ios_unsigned) and allowance in (60, 300))
         and (tuple(methods) != (PACKAGED_METHOD,) or allowance == 60), "test-allowance")
    return ["/usr/bin/xcodebuild", "test-without-building", "-xctestrun", str(manifest),
        "-destination", "platform=macOS,arch=" + machine, "-destination-timeout", "15",
        "-resultBundlePath", str(result), *["-only-testing:" + method for method in methods],
        "-parallel-testing-enabled", "NO", "-test-timeouts-enabled", "YES",
        "-default-test-execution-time-allowance", str(allowance),
        "-maximum-test-execution-time-allowance", str(allowance), "-disableAutomaticPackageResolution"]


def run_admitted_test(call, derived, result, methods, allowance, timeout, *, target=ARM_TARGET, engineering=False, output_data=False, android_positive=False, ios_unsigned=False, removal_case=None):
    normal_target_data(target)
    need(tuple(methods) != (PACKAGED_METHOD,) or target == ARM_TARGET, "fixed-packaged-test-target")
    need(type(engineering) is bool and (not engineering or (target == ARM_TARGET and tuple(methods) == (ENGINEERING_METHOD,) and allowance == 60 and timeout == 180)), "engineering-fixed-test-owner")
    need(type(output_data) is bool and (not output_data or (not engineering and target == ARM_TARGET
         and tuple(methods) == (OUTPUT_DATA_METHOD,) and allowance == 60 and timeout == 120)), "output-data-fixed-test-owner")
    need(type(android_positive) is bool and (not android_positive or (not engineering and not output_data
         and target == ARM_TARGET and tuple(methods) == (CLASS + ANDROID_METHOD,) and allowance == 900
         and timeout == 1020 and Path(result).name == ANDROID_RESULT)), "android-signed-fixed-test-owner")
    need(type(ios_unsigned) is bool and (not ios_unsigned or (not engineering and not output_data and not android_positive
         and tuple(methods) == (CLASS + IOS_UNSIGNED_METHOD,) and allowance == 900 and timeout == 1020
         and Path(result).name == IOS_UNSIGNED_RESULT)), "ios-unsigned-fixed-test-owner")
    if removal_case is not None:
        selected, basename = removal_selection(removal_case)
        need(not any((engineering, output_data, android_positive, ios_unsigned)) and target == ARM_TARGET
             and tuple(methods) == (selected,) and allowance == 300 and timeout == 420
             and Path(result).name == basename, "removal-fixed-test-owner")
    need(not os.path.lexists(result), "fresh-xcresult-required")
    with RunnerProducts(derived) as products:
        facts = products.admit(call)  # Actual generated runner, BEFORE xcodebuild can request any app.
        command = (xcode_test_arguments(products.products / products.manifest, result, methods, allowance, target=target, removal_case=removal_case)
                   if removal_case is not None else xcode_test_arguments(products.products / products.manifest, result, methods, allowance, target=target, ios_unsigned=True)
                   if ios_unsigned else xcode_test_arguments(products.products / products.manifest, result, methods, allowance, target=target, android_positive=True)
                   if android_positive else xcode_test_arguments(products.products / products.manifest, result, methods, allowance, target=target, engineering=True)
                   if engineering else xcode_test_arguments(products.products / products.manifest, result, methods, allowance, target=target, output_data=True)
                   if output_data else xcode_test_arguments(products.products / products.manifest, result, methods, allowance, target=target))
        products.check()
        original = call("one-admitted-ui-test", command, timeout)
        products.check()
        facts["originalProductsPrePostMatched"] = True
    facts["originalClosesCompleted"] = True
    return original, facts


def packaged_ui_result(stdout, summary_body, tests_body):
    text = stdout.decode("utf-8", "strict")
    lines = text.splitlines()
    need(all(lines.count(marker) == 1 for marker in (ORIGINAL_MARKER, ENTRY_MARKER, UI_MARKER))
         and "MRK_MACOS_UI_FAILURE_CLEANUP=" not in text, "original-ui-terminal-markers")
    # A framework retry/restart with zero tests or a second attempt is not a pass.
    selected = "-[MRKNormalAppUITests.NormalAppUITests testPackagedEntryLaunchCancelAndQuit]"
    need(lines.count("Test Case '" + selected + "' started.") == 1
         and len(re.findall(r"^Test Case '" + re.escape(selected) + r"' passed \([0-9.]+ seconds\)\.$", text, re.M)) == 1
         and "Test Case '" + selected + "' failed" not in text, "one-original-test-attempt")
    summary = document(summary_body)
    expected = {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0}
    need(all(type(summary.get(key)) is int and summary[key] == value for key, value in expected.items()),
         "exact-one-passed-test")
    tests = document(tests_body)
    roots = tests.get("testNodes")
    need(type(roots) is list and 0 < len(roots) <= 16, "test-tree-root")
    pending = [(node, (), 0) for node in roots]
    cases, visited = [], 0
    while pending:
        node, ancestors, depth = pending.pop()
        visited += 1
        need(type(node) is dict and visited <= 128 and depth <= 12, "test-tree-bound")
        name, kind = node.get("name"), node.get("nodeType")
        need(type(name) is str and type(kind) is str, "test-tree-node")
        children = node.get("children", [])
        need(type(children) is list and len(children) <= 16, "test-tree-children")
        if kind == "Test Case":
            need(TARGET in ancestors and node.get("result") == "Passed"
                 and name == "testPackagedEntryLaunchCancelAndQuit()"
                 and node.get("nodeIdentifier") in {"NormalAppUITests/testPackagedEntryLaunchCancelAndQuit()",
                                                     PACKAGED_METHOD + "()"}
                 and not children, "exact-selected-passing-test")
            cases.append(node)
        else:
            pending.extend((child, ancestors + (name,), depth + 1) for child in children)
    need(len(cases) == 1, "test-tree-one-case")
    return {"schemaVersion": 1, "scope": "packaged-ordinary-entry-launch-cancel-navigation-quit-ui-only",
        "testIdentifier": PACKAGED_METHOD, "testCounts": expected,
        "nativeSummarySha256": sha(summary_body), "nativeTestTreeSha256": sha(tests_body),
        "oneOriginalXcodebuildZeroRequired": True, "originalReferenceAndGateTerminalObserved": True,
        "payloadProxyMonitoringOnly": True, "normalUICancelNavigationQuitObserved": True,
        "sameBuildQualified": False, "cleanExitStatus": None, "allWorkerFinality": "not-established",
        "fullUIQualified": False, "fullM2Qualified": False, "productReady": False}


def normal_project_markers(stdout):
    """Closed returned-output comparison; not independent native or shipping proof."""
    need(type(stdout) is bytes and 0 < len(stdout) <= 1024 * 1024, "normal-project-output-bound")
    text = stdout.decode("utf-8", "strict")
    lines = text.splitlines()
    methods = ("testSyntheticProjectLocalEditsAndImages", "testSyntheticProjectPathFields")
    markers = (
        "MRK_MACOS_NORMAL_PROJECT_UI=project-config-workflows-text-version-images;cleanExitStatus=unavailable;allWorkerFinality=unavailable",
        "MRK_MACOS_NORMAL_PROJECT_FIELDS_UI=ordinary-four-field-browse-two-cancels-draft-only-invalid-pair-observed;cleanExitStatus=unavailable;allWorkerFinality=unavailable",
        "MRK_MACOS_NORMAL_ANDROID_SOURCE_UI=ordinary-jdk-sdk-gradle-native-cancel-jdk-reselect-backend-source-refused-selection-only;cleanExitStatus=unavailable;allWorkerFinality=unavailable",
    )
    need(lines.count(ORIGINAL_MARKER) == 2 and all(lines.count(marker) == 1 for marker in markers)
         and "MRK_MACOS_UI_FAILURE_CLEANUP=" not in text, "normal-project-terminal-markers")
    selected = {"-[MRKNormalAppUITests.NormalAppUITests " + method + "]" for method in methods}
    starts = re.findall(r"^Test Case '([^'\r\n]{1,240})' started\.$", text, re.M)
    passes = re.findall(r"^Test Case '([^'\r\n]{1,240})' passed \([0-9]+(?:\.[0-9]+)? seconds\)\.$", text, re.M)
    need(len(starts) == 2 and set(starts) == selected, "normal-project-exact-attempts")
    need(len(passes) == 2 and set(passes) == selected
         and re.search(r"^Test Case '[^'\r\n]{1,240}' failed", text, re.M) is None,
         "normal-project-exact-passes")
    return True


def normal_workflow_refusal_markers(stdout):
    """One closed returned-output check; not independent native or shipping proof."""
    need(type(stdout) is bytes and 0 < len(stdout) <= 1024 * 1024
         and stdout.endswith(b"\n"), "normal-workflow-refusal-output-bound")
    text = stdout.decode("utf-8", "strict")
    lines = text.splitlines()
    marker = ("MRK_MACOS_NORMAL_WORKFLOW_REFUSAL_UI="
        "ordinary-preview-customized-candidate-whole-bundle-refused-originals-preserved;"
        "cleanExitStatus=unavailable;allWorkerFinality=unavailable")
    need(lines.count(ORIGINAL_MARKER) == lines.count(marker) == 1
         and sum(line.startswith("MRK_MACOS_UI_ORIGINAL=") for line in lines) == 1
         and sum(line.startswith("MRK_MACOS_NORMAL_WORKFLOW_REFUSAL_UI=") for line in lines) == 1
         and "MRK_MACOS_UI_FAILURE_CLEANUP=" not in text, "normal-workflow-refusal-terminal-markers")
    selected = "-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectManagedWorkflowRefusal]"
    attempts = [line for line in lines if line.startswith("Test Case ")]
    need(len(attempts) == 2 and attempts[0] == "Test Case '" + selected + "' started."
         and re.fullmatch(r"Test Case '" + re.escape(selected)
                          + r"' passed \([0-9]+(?:\.[0-9]+)? seconds\)\.", attempts[1]) is not None,
         "normal-workflow-refusal-exact-attempt-and-pass")
    need(lines.index(attempts[0]) < lines.index(ORIGINAL_MARKER) < lines.index(marker) < lines.index(attempts[1]),
         "normal-workflow-refusal-original-terminal-order")
    return True


def normal_release_evidence_markers(stdout):
    """One closed returned-output check; not independent native or shipping proof."""
    need(type(stdout) is bytes and 0 < len(stdout) <= 1024 * 1024
         and stdout.endswith(b"\n"), "normal-release-evidence-output-bound")
    text = stdout.decode("utf-8", "strict")
    lines = text.splitlines()
    marker = 'MRK_MACOS_NORMAL_RELEASE_EVIDENCE_UI=ordinary-picker-candidate-documents-only-shared-guidance-stage-retained-replacement-cancel-stale-release-inputs-empty-originals-preserved;cleanExitStatus=unavailable;allWorkerFinality=unavailable;remoteRelease=not-attempted'
    need(lines.count(ORIGINAL_MARKER) == lines.count(marker) == 1
         and sum(line.startswith("MRK_MACOS_UI_ORIGINAL=") for line in lines) == 1
         and sum(line.startswith("MRK_MACOS_NORMAL_RELEASE_EVIDENCE_UI=") for line in lines) == 1
         and "MRK_MACOS_UI_FAILURE_CLEANUP=" not in text, "normal-release-evidence-terminal-markers")
    selected = "-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectSavedReleaseEvidence]"
    attempts = [line for line in lines if line.startswith("Test Case ")]
    need(len(attempts) == 2 and attempts[0] == "Test Case '" + selected + "' started."
         and re.fullmatch(r"Test Case '" + re.escape(selected)
                          + r"' passed \([0-9]+(?:\.[0-9]+)? seconds\)\.", attempts[1]) is not None,
         "normal-release-evidence-exact-attempt-and-pass")
    need(lines.index(attempts[0]) < lines.index(ORIGINAL_MARKER) < lines.index(marker) < lines.index(attempts[1]),
         "normal-release-evidence-original-terminal-order")
    return True


def normal_cli_arguments(arguments, *, target=ARM_TARGET):
    machine, _ = normal_target_data(target)
    need(len(arguments) in (25, 26) and arguments[0] == "test-without-building", "normal-fixed-command")
    # Reconstruct the complete old argv; no extra xcodebuild switch may escape.
    need(arguments[11] == "-derivedDataPath" and arguments[13] == "-resultBundlePath", "normal-product-arguments")
    derived, result = Path(arguments[12]), Path(arguments[14])
    need(result.name in NORMAL_SELECTIONS, "normal-existing-selection")
    methods, allowance, timeout = NORMAL_SELECTIONS[result.name]
    expected = ["test-without-building", "-project", PROJECT, "-scheme", "MRKNormalAppUI",
        "-configuration", "Debug", "-destination", "platform=macOS,arch=" + machine,
        "-destination-timeout", "15", "-derivedDataPath", str(derived),
        "-resultBundlePath", str(result), *["-only-testing:" + CLASS + method for method in methods],
        "-parallel-testing-enabled", "NO", "-test-timeouts-enabled", "YES",
        "-default-test-execution-time-allowance", str(allowance),
        "-maximum-test-execution-time-allowance", str(allowance), "-disableAutomaticPackageResolution"]
    need(arguments == expected and result.parent == derived.parent and derived.name == "DerivedData"
         and derived.parent.name == "normal-ui", "normal-exact-command")
    return derived, result, tuple(CLASS + method for method in methods), allowance, timeout



# This fixed opt-in route reuses the normal installed launch/original-command
# owner. It neither enables a product feature nor substitutes an engineering app.
IOS_UNSIGNED_METHOD = "testSyntheticProjectUnsignedIOSArchive"
IOS_UNSIGNED_RESULT = "ios-unsigned-archive-test.xcresult"
IOS_UNSIGNED_PREFIX = b"MRK_MACOS_IOS_UNSIGNED_ARCHIVE_UI="


def ios_unsigned_facts(value, *, source):
    need(type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source), "ios-unsigned-source")
    fixed = dict(schemaVersion=1, scope="one-ordinary-local-unsigned-ios-archive", sourceCommit=source,
        savedVersion="1.2.3", savedBuild=7, inputFiles=9, inputBytes=7264, topLevelDirectories=4,
        archiveDescendantsObserved=False, nativeResultDisplayed=True, outputPostMatched=True,
        originalsClosed=True, normalQuitObserved=True, successBeforeCutoff=True, signed=False,
        ipaExported=False, releaseQualified=False, parentReturncodeRequired=0)
    need(type(value) is dict and set(value) == set(fixed) | {"operationId", "ownerGeneration", "originalEntries", "originalBytes"}
         and all(type(value[k]) is type(v) and value[k] == v for k, v in fixed.items()), "ios-unsigned-closed-facts")
    need(all(type(value[k]) is str and re.fullmatch(r"[0-9a-f]{32}", value[k]) for k in ("operationId", "ownerGeneration")),
         "ios-unsigned-current-pair")
    need(type(value["originalEntries"]) is int and 1 <= value["originalEntries"] <= 100000
         and type(value["originalBytes"]) is int and 1 <= value["originalBytes"] <= 8 << 30,
         "ios-unsigned-original-result-bounds")
    return value


def ios_unsigned_marker(stdout, *, source):
    need(type(stdout) is bytes and 0 < len(stdout) <= 1048576, "ios-unsigned-original-output-bound")
    lines = stdout.splitlines()
    selected = b"-[MRKNormalAppUITests.NormalAppUITests " + IOS_UNSIGNED_METHOD.encode("ascii") + b"]"
    attempts = [line for line in lines if line.startswith(b"Test Case ")]
    need(len(attempts) == 2 and attempts[0] == b"Test Case '" + selected + b"' started."
         and re.fullmatch(rb"Test Case '" + re.escape(selected) + rb"' passed \([0-9]+(?:\.[0-9]+)? seconds\)\.", attempts[1])
         and lines.count(ORIGINAL_MARKER.encode("ascii")) == 1
         and sum(line.startswith(b"MRK_MACOS_UI_ORIGINAL=") for line in lines) == 1
         and not any(b"MRK_MACOS_UI_FAILURE_CLEANUP=" in line for line in lines), "ios-unsigned-one-original-attempt")
    markers = [line[len(IOS_UNSIGNED_PREFIX):] for line in lines if line.startswith(IOS_UNSIGNED_PREFIX)]
    need(len(markers) == 1 and 0 < len(markers[0]) <= 16384, "ios-unsigned-one-closed-marker")
    need(lines.index(attempts[0]) < lines.index(ORIGINAL_MARKER.encode("ascii"))
         < lines.index(IOS_UNSIGNED_PREFIX + markers[0]) < lines.index(attempts[1]), "ios-unsigned-original-terminal-order")
    value = ios_unsigned_facts(document(markers[0]), source=source)
    need(encoded(value) == markers[0], "ios-unsigned-canonical-marker")
    return value


def ios_unsigned_summary(body):
    value = document(body)
    counts = {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0}
    need(all(type(value.get(key)) is int and value[key] == count for key, count in counts.items()), "ios-unsigned-exact-one-pass")
    return counts


SUMMARY_STEMS = {"test.xcresult": "summary", "project-test.xcresult": "project-summary",
    "persistence-test.xcresult": "persistence-summary", "diagnostics-test.xcresult": "diagnostics-summary",
    "saved-checks-test.xcresult": "saved-checks-summary",
    "workflow-refusal-test.xcresult": "workflow-refusal-summary",
    "release-evidence-test.xcresult": "release-evidence-summary",
    "saved-version-recovery-test.xcresult": "saved-version-recovery-summary",
    IOS_UNSIGNED_RESULT: "ios-unsigned-archive-summary"}
TOOLCHAIN_QUERIES = (
    ("xcode", "xcode-version.txt", ("/usr/bin/xcodebuild", "-version")),
    ("sdkPath", "sdk-path.txt", ("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path")),
    ("sdkVersion", "sdk-version.txt", ("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version")),
    ("sdkBuild", "sdk-build.txt", ("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-build-version")),
)


def normal_request(arguments, temporary):
    """Fixed modes with one optional leading target; ARM remains the default."""
    need(type(arguments) is list and all(type(value) is str for value in arguments), "normal-fixed-command")
    target = ARM_TARGET
    if arguments[:1] == ["--target"]:
        need(len(arguments) >= 3, "normal-target-arguments")
        target, arguments = arguments[1], arguments[2:]
    normal_target_data(target)
    need("--target" not in arguments, "normal-target-arguments")
    need(type(temporary) is str, "normal-fixed-tmpdir")
    normal = Path(temporary).parent
    if arguments == ["--normal-build"]:
        value = dict(phase="build", derived=normal / "DerivedData", result=None,
                     methods=(), allowance=None, timeout=240, phaseSeconds=450)
    elif arguments in (["--normal-android-signed-build-test"], ["--normal-android-signed-build-summary"]):
        need(target == ARM_TARGET, "android-signed-arm-only")
        testing = arguments[0].endswith("-test")
        value = dict(phase="test" if testing else "summary", derived=normal / "DerivedData", result=normal / ANDROID_RESULT,
            methods=(CLASS + ANDROID_METHOD,) if testing else (), allowance=900 if testing else None,
            timeout=1020 if testing else 30, phaseSeconds=1245 if testing else 90, androidPositive=True)
    elif arguments in (["--normal-ios-unsigned-archive-test"], ["--normal-ios-unsigned-archive-summary"]):
        testing = arguments[0].endswith("-test")
        value = dict(phase="test" if testing else "summary", derived=normal / "DerivedData", result=normal / IOS_UNSIGNED_RESULT,
            methods=(CLASS + IOS_UNSIGNED_METHOD,) if testing else (), allowance=900 if testing else None,
            timeout=1020 if testing else 30, phaseSeconds=1245 if testing else 90, iosUnsigned=True)
    elif arguments == ["--normal-output-data-test"]:
        need(target == ARM_TARGET, "output-data-arm-only")
        value = dict(phase="test", derived=normal / "DerivedData", result=normal / OUTPUT_DATA_RESULT,
                     methods=(OUTPUT_DATA_METHOD,), allowance=60, timeout=120, phaseSeconds=345, outputData=True)
    elif len(arguments) == 2 and arguments[0] == "--normal-summary":
        need(arguments[1] in NORMAL_SELECTIONS, "normal-summary-selection")
        value = dict(phase="summary", derived=normal / "DerivedData", result=normal / arguments[1],
                     methods=(), allowance=None, timeout=30, phaseSeconds=90)
    else:
        derived, result, methods, allowance, timeout = normal_cli_arguments(arguments, target=target)
        value = dict(phase="test", derived=derived, result=result, methods=methods,
                     allowance=allowance, timeout=timeout,
                     phaseSeconds=345 if timeout == 180 else 885 if timeout == 720 else 585)
    need(value["derived"].is_absolute() and value["derived"].parent.name == "normal-ui"
         and temporary == str(value["derived"].parent / "tmp") + "/", "normal-fixed-tmpdir")
    value["target"] = target
    return value


def normal_file_limit(phase, actual):
    need(phase in ("build", "test", "summary"), "normal-file-budget-phase")
    expected = 32 * 1024**3 if phase == "build" else 1024**3
    need(type(actual) is tuple and len(actual) == 2 and all(type(n) is int for n in actual)
         and actual == (expected, expected), "normal-host-developer-file-budget")
    return actual


class PhaseClock:
    """One immutable endpoint, including original-owner cleanup and publication."""
    def __init__(self, seconds, *, now=None, started=None):
        self.now = time.monotonic_ns if now is None else now
        self.started = self.now() if started is None else started
        need(type(seconds) is int and seconds > 0 and type(self.started) is int and self.started >= 0,
             "normal-phase-clock")
        self.deadline = self.started + seconds * 1_000_000_000
        self.last = self.started
        self.failed = False
        self.finalized = False
        self.check()

    def check(self):
        need(not self.failed and not self.finalized, "normal-phase-terminal")
        value = self.now()
        if type(value) is not int or value < self.last or value < 0 or value >= self.deadline:
            self.failed = True
            raise Refused("normal-phase-deadline-or-clock")
        self.last = value
        return value

    def allowance(self, cap):
        current = self.check()
        # Existing owner CLEANUP_NS=3s, plus10s for this phase's final publication.
        remaining = (self.deadline - current - 13_000_000_000) // 1_000_000_000
        if type(cap) is not int or cap < 1 or remaining < 1:
            self.failed = True
            raise Refused("normal-phase-no-command-budget")
        return min(cap, remaining)

    def before_publication(self):
        current = self.check()
        return {"startNs": str(self.started), "deadlineNs": str(self.deadline),
                "beforePublicationNs": str(current), "postCloseDeadlineRequired": True}

    def finish(self):
        self.check()
        self.finalized = True


def original_command(value, argv, limit):
    need(type(value) is subprocess.CompletedProcess and type(value.args) is list and value.args == argv
         and type(value.returncode) is int and 0 <= value.returncode <= 255
         and type(value.stdout) is bytes and type(value.stderr) is bytes
         and len(value.stdout) + len(value.stderr) <= limit, "normal-original-command")
    return value


class NormalPhase:
    def __init__(self, owner, environment, root, clock, *, retain_nonzero=False):
        need(type(retain_nonzero) is bool, "normal-nonzero-retention-mode")
        self.owner, self.environment, self.root, self.clock = owner, environment, root, clock
        self.records = []
        self.retain_nonzero, self.first_nonzero = retain_nonzero, None

    def call(self, role, argv, seconds, limit=1024 * 1024):
        try:
            actual = self.clock.allowance(seconds)
            value = self.owner.run_owned(argv, environ=self.environment, cwd=self.root, timeout=actual,
                                        capture=True, text=False, output_limit=limit)
            original_command(value, argv, limit)
            if self.retain_nonzero and self.first_nonzero is None and value.returncode != 0:
                self.first_nonzero = value  # Exact admitted original, before any later clock/format/close can fail.
            self.records.append({"role": role, "returncode": value.returncode,
                "timeoutSeconds": actual, "roleCapSeconds": seconds, "outputLimitBytes": limit,
                "argvSha256": sha(encoded(argv)), "stdoutBytes": len(value.stdout), "stdoutSha256": sha(value.stdout),
                "stderrBytes": len(value.stderr), "stderrSha256": sha(value.stderr)})
            self.clock.check()
            return value
        except BaseException:
            self.clock.failed = True
            raise


def exclusive_output(path, body, limit, *, allow_empty=False):
    """No overwrite/reopen; original complete readback and consuming close."""
    need(type(allow_empty) is bool and type(body) is bytes and (0 if allow_empty else 1) <= len(body) <= limit, "normal-output-bound")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        initial = os.fstat(fd)
        need(stat.S_ISREG(initial.st_mode) and stat.S_IMODE(initial.st_mode) == 0o600
             and initial.st_uid == os.getuid() and initial.st_gid == os.getgid()
             and initial.st_nlink == 1 and initial.st_size == 0, "normal-output-original")
        offset = 0
        while offset < len(body):
            count = os.write(fd, body[offset:])
            need(type(count) is int and 0 < count <= len(body) - offset, "normal-output-write")
            offset += count
        os.fsync(fd)
        observed, identity, digest = original_body(fd, limit, collect=True)
        need(observed == body and digest == sha(body) and identity[6] == len(body)
             and full9(os.stat(path, follow_symlinks=False)) == identity, "normal-output-readback")
    finally:
        os.close(fd)  # Original consumed once; a close failure never authorizes retry.


def normal_toolchain(values):
    need(type(values) is dict and set(values) == {q[0] for q in TOOLCHAIN_QUERIES}, "normal-toolchain-fields")
    text = {}
    for key, body in values.items():
        need(type(body) is bytes and 0 < len(body) <= 512, "normal-toolchain-bound")
        value = body.decode("ascii", "strict")
        text[key] = value[:-1] if value.endswith("\n") else value
    version = r"26(?:\.[0-9]{1,3}){0,3}"
    need(re.fullmatch(r"Xcode " + version + r"\nBuild version [0-9A-Za-z]{1,32}", text["xcode"])
         and re.fullmatch(version, text["sdkVersion"])
         and re.fullmatch(r"[0-9A-Za-z]{1,32}", text["sdkBuild"]), "normal-toolchain-version")
    prefix = (r"/Applications/Xcode(?:_" + version + r")?\.app/Contents/Developer"
              r"/Platforms/MacOSX\.platform/Developer/SDKs/")
    need(re.fullmatch(prefix + r"MacOSX(?:" + re.escape(text["sdkVersion"]) + r")?\.sdk", text["sdkPath"]),
         "normal-toolchain-sdk-path")
    return text


def normal_build_arguments(derived, *, target=ARM_TARGET):
    machine, _ = normal_target_data(target)
    return ["/usr/bin/xcodebuild", "build-for-testing", "-project", PROJECT, "-scheme", "MRKNormalAppUI",
        "-configuration", "Debug", "-destination", "platform=macOS,arch=" + machine, "-destination-timeout", "15",
        "-derivedDataPath", str(derived), "-jobs", "2", "-disableAutomaticPackageResolution",
        "COMPILER_INDEX_STORE_ENABLE=NO"] + (["ARCHS=x86_64"] if target == INTEL_TARGET else [])


def normal_source_state(phase, source):
    arguments = ["/usr/bin/git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
        "ls-tree", "-r", "-z", "--full-tree", source, "--", "desktop/native/macos-normal-ui",
        "desktop/tools/macos_normal_ui_runner.py"]
    original = phase.call("normal-ui-source-roster", arguments, 15)
    need(original.returncode == 0 and len(original.stdout) <= 8192, "normal-ui-source-command")
    rows = original.stdout.split(b"\0")
    need(rows[-1] == b"" and 0 < len(rows) <= 16, "normal-ui-source-roster")
    facts = {}
    for row in rows[:-1]:
        header, raw_name = row.split(b"\t", 1)
        mode, kind, blob = header.split(b" ")
        name = raw_name.decode("utf-8", "strict")
        need(kind == b"blob" and mode in (b"100644", b"100755")
             and (name.startswith("desktop/native/macos-normal-ui/") or name == "desktop/tools/macos_normal_ui_runner.py")
             and all(part not in ("", ".", "..") for part in name.split("/")) and name not in facts,
             "normal-ui-source-entry")
        fd = os.open(phase.root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            body, identity, digest = original_body(fd, 1024 * 1024, collect=True)
            need(hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest() == blob.decode("ascii")
                 and full9(os.stat(phase.root / name, follow_symlinks=False)) == identity, "normal-ui-source-correspondence")
            facts[name] = [decimal(identity), digest]
        finally:
            os.close(fd)
    need("desktop/tools/macos_normal_ui_runner.py" in facts
         and "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift" in facts,
         "normal-ui-source-complete")
    return facts


# One fixed same-job PRIVATE input reader. It owns descriptors, never commands,
# product authority, vendor acceptance, source mutation or private-file deletion.
ANDROID_RESULT = "android-signed-build-test.xcresult"
ANDROID_METHOD = "testSyntheticProjectAndroidSignedBuild"
ANDROID_WORKFLOW = ".github/workflows/desktop-macos-installed.yml"
ANDROID_REF = "refs/heads/verify/desktop-macos-installed"
ANDROID_INPUT_ENV = "TEST_RUNNER_MRK_NORMAL_UI_ANDROID_INPUT_FIXTURE"
ANDROID_RUN_ENV = "TEST_RUNNER_MRK_NORMAL_UI_ANDROID_RUN_ID"
ANDROID_ATTEMPT_ENV = "TEST_RUNNER_MRK_NORMAL_UI_ANDROID_RUN_ATTEMPT"
ANDROID_CATALOGUE = "1d1c1f0f49836180853285d49e114b12c44c9d72c41250b103c5dd34fa792203"
ANDROID_ROOTS = {"jdk": "tools/jdk/temurin-17.jdk", "sdk": "tools/sdk", "gradle": "tools/gradle"}
ANDROID_PRIVATE_FILES = ("upload.jks", "upload.der", "scalars.json")


def android_input_document(body, *, source, run, attempt, root):
    """Closed PRIVATE DATA only; actual producer0 remains a separate owner gate."""
    need(type(body) is bytes and 0 < len(body) <= 16384, "android-input-document-bound")
    value = document(body)
    need(set(value) == {"schemaVersion", "scope", "sourceCommit", "target", "runId", "runAttempt",
        "workflow", "ref", "root", "rootFacts", "credentialDirectoryFacts", "sourceCatalogueSha256",
        "sourceRosterSha256", "roots", "files", "publicCertificateSha256", "keyCommands",
        "parentReturncodeRequired", "phaseClock"} and encoded(value) + b"\n" == body,
        "android-input-canonical-shape")
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["scope"] == "one-owned-android-ui-inputs" and value["sourceCommit"] == source
         and type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source)
         and value["target"] == ARM_TARGET and value["workflow"] == ANDROID_WORKFLOW
         and value["ref"] == ANDROID_REF and value["root"] == str(root)
         and value["runId"] == run and value["runAttempt"] == attempt
         and all(type(x) is str and re.fullmatch(r"[1-9][0-9]{0,19}", x) for x in (run, attempt))
         and value["sourceCatalogueSha256"] == ANDROID_CATALOGUE
         and type(value["parentReturncodeRequired"]) is int and value["parentReturncodeRequired"] == 0,
         "android-input-current-context")
    def digest(item):
        return type(item) is str and re.fullmatch(r"[0-9a-f]{64}", item) is not None
    def facts(item):
        return (type(item) is list and len(item) == 10 and all(type(x) is str
                and re.fullmatch(r"0|[1-9][0-9]{0,19}", x) for x in item))
    need(facts(value["rootFacts"]) and facts(value["credentialDirectoryFacts"])
         and digest(value["sourceRosterSha256"]) and digest(value["publicCertificateSha256"]),
         "android-input-facts-shape")
    need(type(value["roots"]) is dict and set(value["roots"]) == set(ANDROID_ROOTS)
         and type(value["files"]) is dict and set(value["files"]) == set(ANDROID_PRIVATE_FILES),
         "android-input-fixed-roster")
    for role, relative in ANDROID_ROOTS.items():
        row = value["roots"][role]
        need(type(row) is dict and set(row) == {"relative", "facts"}
             and row["relative"] == relative and facts(row["facts"]), "android-input-source-row")
    for name in ANDROID_PRIVATE_FILES:
        row = value["files"][name]
        need(type(row) is dict and set(row) == {"relative", "facts", "sha256"}
             and row["relative"] == "credentials/" + name and facts(row["facts"])
             and digest(row["sha256"]), "android-input-private-row")
    clock = value["phaseClock"]
    need(type(clock) is dict and set(clock) == {"startNs", "deadlineNs", "beforePublicationNs", "postCloseDeadlineRequired"}
         and clock["postCloseDeadlineRequired"] is True
         and all(type(clock[k]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", clock[k])
                 for k in ("startNs", "deadlineNs", "beforePublicationNs")), "android-input-clock-shape")
    need(int(clock["deadlineNs"]) - int(clock["startNs"]) == 1200 * 10**9
         and int(clock["startNs"]) <= int(clock["beforePublicationNs"]) < int(clock["deadlineNs"]),
         "android-input-original-clock")
    rows = value["keyCommands"]
    need(type(rows) is list and len(rows) == 2, "android-input-key-commands")
    for row, role in zip(rows, ("android-ui-disposable-jks", "android-ui-public-certificate")):
        need(type(row) is dict and set(row) == {"role", "returncode", "timeoutSeconds", "roleCapSeconds",
            "outputLimitBytes", "argvSha256", "stdoutBytes", "stdoutSha256", "stderrBytes", "stderrSha256"}
             and row["role"] == role and all(type(row[k]) is int for k in
                 ("returncode", "timeoutSeconds", "roleCapSeconds", "outputLimitBytes", "stdoutBytes", "stderrBytes"))
             and row["returncode"] == 0 and row["roleCapSeconds"] == 30 and 1 <= row["timeoutSeconds"] <= 30
             and row["outputLimitBytes"] == 2097152 and 0 <= row["stdoutBytes"] <= 2097152
             and 0 <= row["stderrBytes"] <= 2097152 - row["stdoutBytes"]
             and all(digest(row[k]) for k in ("argvSha256", "stdoutSha256", "stderrSha256")),
             "android-input-key-command-shape")
    return value


def android_input_scalars(body):
    need(type(body) is bytes and 0 < len(body) <= 32768, "android-input-scalar-bound")
    value = document(body)
    need(set(value) == {"alias", "storePassword", "keyPassword"} and encoded(value) + b"\n" == body
         and value["alias"] == "mrk-disposable-android-ui"
         and all(type(value[k]) is str and re.fullmatch(r"[0-9a-f]{48}", value[k])
                 for k in ("storePassword", "keyPassword")), "android-input-scalar-shape")
    return value


class AndroidPrivateInputs:
    """At most14 retained directories+4 leaves; no vendor traversal or execution."""
    def __init__(self, phase, source, normal):
        self.phase, self.source, self.normal = phase, source, Path(normal)
        self.root = self.normal / "android-inputs"
        self.fds, self.directories, self.files = [], [], {}
        self.closed = False
        self.public_certificate = None
        self.credentials = None

    def adopt_directory(self, parent, name, *, full=False, private=False):
        self.phase.clock.check()
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     **({"dir_fd": parent} if parent is not None else {}))
        self.fds.append(fd)
        observed = saved_version_facts(os.fstat(fd))
        named = saved_version_facts(os.stat(name, dir_fd=parent, follow_symlinks=False))
        need(stat.S_ISDIR(observed[2]) and observed == named and observed[3] in (0, os.getuid())
             and not observed[2] & 0o022 and observed[9] == 0, "android-input-directory-original")
        if private:
            need(observed[3:5] == (os.getuid(), os.getgid()) and observed[2] & 0o7777 == 0o700,
                 "android-input-private-directory")
        self.directories.append((fd, parent, name, observed, full))
        need(len(self.directories) <= 14, "android-input-directory-count")
        return fd, observed

    def read(self, parent, name, limit):
        self.phase.clock.check()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        self.fds.append(fd)
        before = saved_version_facts(os.fstat(fd))
        need(stat.S_ISREG(before[2]) and before[2] & 0o7777 == 0o600 and before[3:5] == (os.getuid(), os.getgid())
             and before[5] == 1 and 0 < before[6] <= limit and before[9] == 0
             and before[0] == os.fstat(parent).st_dev, "android-input-private-file")
        body, _, digest = original_body(fd, limit, collect=True)
        need(saved_version_facts(os.fstat(fd)) == before
             and saved_version_facts(os.stat(name, dir_fd=parent, follow_symlinks=False)) == before,
             "android-input-file-post")
        self.files[name] = (fd, parent, before, digest, limit)
        self.phase.clock.check()
        return body, before, digest

    def __enter__(self):
        try:
            fd, _ = self.adopt_directory(None, "/")
            for name in self.normal.parts[1:]:
                fd, _ = self.adopt_directory(fd, name, private=name == "normal-ui" or name.startswith("mrk-macos-installed."))
            normal = fd
            body, _, _ = self.read(normal, "android-input-fixture.json", 16384)
            value = android_input_document(body, source=self.source,
                run=self.phase.environment[ANDROID_RUN_ENV], attempt=self.phase.environment[ANDROID_ATTEMPT_ENV], root=self.root)
            root, root_facts = self.adopt_directory(normal, "android-inputs", full=True, private=True)
            credentials, credential_facts = self.adopt_directory(root, "credentials", full=True, private=True)
            need(decimal(root_facts) == value["rootFacts"] and decimal(credential_facts) == value["credentialDirectoryFacts"],
                 "android-input-current-private-roots")
            self.credentials = credentials
            tools, _ = self.adopt_directory(root, "tools", full=True, private=True)
            jdk, jdk_facts = self.adopt_directory(tools, "jdk", full=True)
            need(jdk_facts[3:5] == (os.getuid(), os.getgid()) and jdk_facts[2] & 0o7777 == 0o755
                 and jdk_facts[0] == root_facts[0], "android-input-source-parent")
            roots = {"jdk": self.adopt_directory(jdk, "temurin-17.jdk", full=True),
                     "sdk": self.adopt_directory(tools, "sdk", full=True),
                     "gradle": self.adopt_directory(tools, "gradle", full=True)}
            for role, (_, observed) in roots.items():
                need(decimal(observed) == value["roots"][role]["facts"]
                     and observed[3:5] == (os.getuid(), os.getgid()) and observed[0] == root_facts[0]
                     and observed[2] & 0o7777 == 0o755,
                     "android-input-current-source-root")
            total = len(body)
            for name in ANDROID_PRIVATE_FILES:
                raw, observed, digest = self.read(credentials, name, 32768)
                total += len(raw)
                need(decimal(observed) == value["files"][name]["facts"] and digest == value["files"][name]["sha256"],
                     "android-input-current-private-leaf")
                if name == "scalars.json":
                    android_input_scalars(raw)
                if name == "upload.der":
                    need(digest == value["publicCertificateSha256"], "android-input-public-certificate")
                raw = None
            need(total <= 256 * 1024 and len(self.fds) == 18 and len(self.files) == 4, "android-input-whole-census")
            self.public_certificate = value["publicCertificateSha256"]
            self.post()
            return self
        except BaseException:
            self.close(primary=True)
            raise

    def post(self):
        need(not self.closed, "android-input-already-closed")
        self.phase.clock.check()
        for fd, parent, name, before, full in self.directories:
            observed = saved_version_facts(os.fstat(fd))
            named = saved_version_facts(os.stat(name, dir_fd=parent, follow_symlinks=False))
            indices = range(10) if full else (0, 1, 2, 3, 4, 9)
            need(all(before[i] == observed[i] == named[i] for i in indices), "android-input-ancestor-post")
        if self.credentials is not None:
            names = []
            with os.scandir(self.credentials) as entries:
                for entry in entries:
                    need(len(names) < 3, "android-input-private-name-bound")
                    names.append(entry.name)
            need(set(names) == set(ANDROID_PRIVATE_FILES), "android-input-private-names")
        for name, (fd, parent, before, digest, limit) in self.files.items():
            _, _, current = original_body(fd, limit)
            need(current == digest and saved_version_facts(os.fstat(fd)) == before
                 and saved_version_facts(os.stat(name, dir_fd=parent, follow_symlinks=False)) == before,
                 "android-input-private-post")
            self.phase.clock.check()

    def close(self, *, primary=False):
        if self.closed:
            return
        error = None
        while self.fds:
            fd = self.fds.pop()  # Consume before close; never retry an ambiguous descriptor.
            try:
                os.close(fd)
            except BaseException as failure:
                if error is None:
                    error = failure
        self.closed = True
        self.directories.clear()
        self.files.clear()
        self.credentials = None
        try:
            self.phase.clock.check()
        except BaseException as failure:
            if error is None:
                error = failure
        if error is not None and not primary:
            raise Refused("android-input-close-or-clock") from None

    def __exit__(self, kind, value, traceback):
        primary = value
        if primary is None:
            try:
                self.post()
            except BaseException as failure:
                primary = failure
        self.close(primary=primary is not None)
        if primary is not None and value is None:
            raise primary
        return False


ANDROID_FACTS_SCOPE = "one-ordinary-local-signed-android-build"
ANDROID_FACTS_PREFIX = b"MRK_MACOS_ANDROID_SIGNED_BUILD_UI="


def publish_android_signed_failure(request, stage, code):
    need(stage in {"request", "context", "loader", "phase", "execute", "diagnostic", "publication", "finalize"}
         and type(code) is int and code != 0, "android-signed-failure-shape")
    body = encoded(dict(schemaVersion=1, scope="android-signed-ui-closed-failure", stage=stage,
        originalStatus=code, qualification=False, cleanupAuthorized=False)) + b"\n"
    exclusive_output(request["derived"].parent / "android-signed-build.failure.json", body, 1024)


def android_signed_facts(value, *, source, run, attempt):
    """Safe public fields only; command/credential relations remain PRIVATE."""
    need(type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source)
         and all(type(item) is str and re.fullmatch(r"[1-9][0-9]{0,19}", item) for item in (run, attempt)),
         "android-signed-public-context")
    fixed = dict(schemaVersion=1, scope=ANDROID_FACTS_SCOPE, sourceCommit=source,
        target=ARM_TARGET, runId=run, runAttempt=attempt, sourceRegistrationObserved=False,
        nativeSigningVerified=True, privateOriginalsClosed=True, memorySessionDiscarded=True, parentReturncodeRequired=0,
        outputPostMatched=True, normalQuitObserved=True, releaseQualified=False)
    variable = {"operationId", "ownerGeneration", "publicCertificateSha256", "artifactSha256", "artifactBytes",
                "outputEntries", "outputNameBytes", "outputLogicalBytes", "moduleLogicalBytes", "outputCensusSha256"}
    need(type(value) is dict and set(value) == set(fixed) | variable
         and all(type(value[k]) is type(v) and value[k] == v for k, v in fixed.items())
         and len(encoded(value)) <= 16384, "android-signed-public-facts")
    for key in ("operationId", "ownerGeneration"):
        need(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{32}", value[key]), "android-signed-current-id")
    for key in ("publicCertificateSha256", "artifactSha256", "outputCensusSha256"):
        need(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{64}", value[key]), "android-signed-public-digest")
    bounds = {"artifactBytes": 64 << 20, "outputEntries": 100000, "outputNameBytes": 2 << 20,
              "outputLogicalBytes": 2 << 30, "moduleLogicalBytes": 1 << 30}
    need(all(type(value[k]) is int and 0 < value[k] <= cap for k, cap in bounds.items())
         and value["outputLogicalBytes"] >= value["moduleLogicalBytes"] + value["artifactBytes"],
         "android-signed-output-census")
    return value


def android_signed_marker(stdout, *, source, run, attempt, certificate):
    need(type(stdout) is bytes and len(stdout) <= 1048576, "android-signed-private-output-bound")
    lines = stdout.splitlines()
    selected = b"-[MRKNormalAppUITests.NormalAppUITests " + ANDROID_METHOD.encode("ascii") + b"]"
    need(lines.count(b"Test Case '" + selected + b"' started.") == 1
         and sum(re.fullmatch(rb"Test Case '" + re.escape(selected) + rb"' passed \([0-9.]+ seconds\)\.", line) is not None for line in lines) == 1
         and not any(b"Test Case '" + selected + b"' failed" in line for line in lines)
         and lines.count(ORIGINAL_MARKER.encode("ascii")) == 1
         and not any(b"MRK_MACOS_UI_FAILURE_CLEANUP=" in line for line in lines), "android-signed-one-original-attempt")
    markers = [line[len(ANDROID_FACTS_PREFIX):] for line in lines if line.startswith(ANDROID_FACTS_PREFIX)]
    need(len(markers) == 1 and 0 < len(markers[0]) <= 16384, "android-signed-one-public-marker")
    facts = android_signed_facts(document(markers[0]), source=source, run=run, attempt=attempt)
    need(facts["publicCertificateSha256"] == certificate and encoded(facts) == markers[0], "android-signed-original-certificate")
    return facts


def android_signed_summary(body):
    value = document(body)
    counts = {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0}
    need(all(type(value.get(key)) is int and value[key] == count for key, count in counts.items()),
         "android-signed-exact-one-pass")
    return counts


def execute_android_signed_phase(phase, request, source, file_limit):
    """Fixed installed role; actual supplier original0 is an independent workflow gate."""
    normal = request["derived"].parent
    before = normal_source_state(phase, source)
    run, attempt = phase.environment[ANDROID_RUN_ENV], phase.environment[ANDROID_ATTEMPT_ENV]
    public = None
    if request["phase"] == "test":
        with AndroidPrivateInputs(phase, source, normal) as inputs:
            original, runner = run_admitted_test(phase.call, request["derived"], request["result"],
                request["methods"], 900, 1020, target=ARM_TARGET, android_positive=True)
            if original.returncode == 0:
                public = android_signed_marker(original.stdout, source=source, run=run, attempt=attempt,
                                               certificate=inputs.public_certificate)
        # __exit__ performs private POST/all consuming closes/clock before this fact.
        facts = dict(schemaVersion=1, scope="android-signed-private-original-admission", phase="test",
            resultBundle=ANDROID_RESULT, originalCommandRole="one-admitted-ui-test", originalReturncode=original.returncode,
            runnerAdmission=runner, parentPrivateOriginalsClosed=True, observation=public)
        receipt = normal / "android-signed-build-test.runner-admission.json"
    else:
        need(request["phase"] == "summary", "android-signed-fixed-phase")
        observed = os.stat(request["result"], follow_symlinks=False)
        need(stat.S_ISDIR(observed.st_mode) and observed.st_uid == os.getuid() and not observed.st_mode & 0o022,
             "android-signed-summary-result-original")
        original = phase.call("normal-ui-summary", ["/usr/bin/xcrun", "xcresulttool", "get", "test-results", "summary",
            "--path", str(request["result"]), "--compact"], 30, 262144)
        counts = android_signed_summary(original.stdout) if original.returncode == 0 else None
        facts = dict(schemaVersion=1, scope="android-signed-private-original-admission", phase="summary",
            resultBundle=ANDROID_RESULT, originalCommandRole="normal-ui-summary", originalReturncode=original.returncode,
            testCounts=counts)
        receipt = normal / "android-signed-build-summary.command-admission.json"
    need(normal_source_state(phase, source) == before, "android-signed-source-pre-post")
    facts.update(sourceCommit=source, target=ARM_TARGET, runId=run, runAttempt=attempt,
        sourceRosterSha256=sha(encoded(before)), sourcePrePostMatched=True, originalCommandReturned=True,
        commands=phase.records, fileLimitBytes=list(file_limit), phaseClock=phase.clock.before_publication(),
        receiptPolicy="exclusive0600-readback-consuming-close")
    exclusive_output(receipt, encoded(facts) + b"\n", 32768)
    phase.clock.check()
    if public is not None:
        exclusive_output(normal / "android-signed-build.facts.json", encoded(public) + b"\n", 16384)
        phase.clock.check()
    return original


def android_signed_receipts(build, test, summary, facts, *, source, normal, run, attempt):
    """Read-only local PRIVATE receipt join. Actual step statuses0 remain separate."""
    normal = Path(normal)
    android_signed_facts(facts, source=source, run=run, attempt=attempt)
    need(type(build) is dict and type(build.get("sourceRosterSha256")) is str
         and re.fullmatch(r"[0-9a-f]{64}", build["sourceRosterSha256"]), "android-signed-build-roster")
    roster = build["sourceRosterSha256"]
    output_data_build_receipt(build, source, normal, roster)
    source_command = ("normal-ui-source-roster", 15, 1048576, output_data_source_argv(source))
    common = dict(schemaVersion=1, scope="android-signed-private-original-admission", resultBundle=ANDROID_RESULT,
        sourceCommit=source, target=ARM_TARGET, runId=run, runAttempt=attempt, sourceRosterSha256=roster,
        sourcePrePostMatched=True, originalCommandReturned=True, originalReturncode=0,
        fileLimitBytes=[1024**3] * 2, receiptPolicy="exclusive0600-readback-consuming-close")
    for receipt, mode, cap in ((test, "test", 1245), (summary, "summary", 90)):
        expected = dict(common, phase=mode, originalCommandRole="one-admitted-ui-test" if mode == "test" else "normal-ui-summary")
        extra = {"runnerAdmission", "parentPrivateOriginalsClosed", "observation"} if mode == "test" else {"testCounts"}
        need(type(receipt) is dict and set(receipt) == set(expected) | extra | {"commands", "phaseClock"}
             and all(type(receipt[k]) is type(v) and receipt[k] == v for k, v in expected.items()),
             "android-signed-private-receipt-shape")
        output_data_clock(receipt["phaseClock"], cap)
    need(test["parentPrivateOriginalsClosed"] is True and encoded(test["observation"]) == encoded(facts)
         and summary["testCounts"] == {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0}
         and all(type(x) is int for x in summary["testCounts"].values()), "android-signed-private-receipt-outcome")
    runner = test["runnerAdmission"]
    fixed = dict(schemaVersion=1, scope="actual-generated-xctrunner-admission-only",
        runnerPath=str(normal / "DerivedData/Build/Products" / RUNNER), strictCodesignOriginalZero=True,
        reSignedOrRepaired=False, originalProductsPrePostMatched=True, originalClosesCompleted=True)
    need(type(runner) is dict and set(runner) == set(fixed) | {"xctestrunPath", "runnerExecutable", "testExecutable", "xctestrun",
         "productEntryCount", "productRosterSha256", "entitlementsSha256", "appSandboxEntitlement"}
         and all(type(runner[k]) is type(v) and runner[k] == v for k, v in fixed.items())
         and runner["appSandboxEntitlement"] in ("absent", "false") and type(runner["productEntryCount"]) is int
         and 5 <= runner["productEntryCount"] <= 4096, "android-signed-runner-admission")
    manifest = runner["xctestrunPath"]
    need(type(manifest) is str and len(manifest) <= 2048 and Path(manifest).parent == normal / "DerivedData/Build/Products"
         and re.fullmatch(r"MRKNormalAppUI_macosx[0-9A-Za-z_.-]+\.xctestrun", Path(manifest).name), "android-signed-runner-manifest")
    for key in ("runnerExecutable", "testExecutable", "xctestrun"):
        row = runner[key]
        need(type(row) is list and len(row) == 3 and row[0] == "file" and type(row[1]) is list and len(row[1]) == 9
             and all(type(part) is str and re.fullmatch(r"[0-9]{1,20}", part) for part in row[1])
             and stat.S_ISREG(int(row[1][2])) and int(row[1][5]) == 1 and 0 < int(row[1][6]) <= 256 << 20
             and type(row[2]) is str and re.fullmatch(r"[0-9a-f]{64}", row[2]), "android-signed-runner-original")
    need(all(type(runner[k]) is str and re.fullmatch(r"[0-9a-f]{64}", runner[k])
             for k in ("productRosterSha256", "entitlementsSha256")), "android-signed-runner-roster")
    command = xcode_test_arguments(Path(manifest), normal / ANDROID_RESULT, (CLASS + ANDROID_METHOD,), 900, android_positive=True)
    output_data_records(test["commands"], [source_command,
        ("verify-generated-runner", 30, 1048576, ["/usr/bin/codesign", "--verify", "--strict", runner["runnerPath"]]),
        ("generated-runner-entitlements", 30, 1048576, ["/usr/bin/codesign", "-d", "--entitlements", ":-", runner["runnerPath"]]),
        ("one-admitted-ui-test", 1020, 1048576, command), source_command])
    output_data_records(summary["commands"], [source_command, ("normal-ui-summary", 30, 262144,
        ["/usr/bin/xcrun", "xcresulttool", "get", "test-results", "summary", "--path", str(normal / ANDROID_RESULT), "--compact"]), source_command])



# One fixed real producer -> ordinary UI handoff. No journal is synthesized here,
# no product recovery authority is exported, and no fixture is deleted by this owner.
SAVED_VERSION_RESULT = "saved-version-recovery-test.xcresult"
SAVED_VERSION_TEMPORARY = Path("/private/tmp")
SAVED_VERSION_PRODUCER = "tests/desktop/test_saved_text_recovery.py"
SAVED_VERSION_DATA = "desktop/native/macos-normal-ui/MRKNormalAppUITests/Fixtures/normal-project-v1.json"
SAVED_VERSION_SOURCE = "fa624512af03437f075f2da10357b3808d1a58c8f36e1db6103bc2abe54150e0"
SAVED_VERSION_PATH = "project/release/version.properties"
SAVED_VERSION_JOURNAL = "project/.mobile-release-version"
SAVED_VERSION_ENV = "TEST_RUNNER_MRK_NORMAL_UI_SAVED_VERSION_FIXTURE"
SAVED_VERSION_MARKER = ("MRK_MACOS_NORMAL_SAVED_VERSION_RECOVERY_UI="
    "original-core-interrupt86-fresh-ui-inspect-close-reinspect-confirm-rollback-reload;"
    "interruptedGuiSave=not-observed;cleanExitStatus=unavailable;allWorkerFinality=unavailable")
SAVED_VERSION_CONTROLS = ("header.json", "plan.json", "commit.pending", "rollback.pending", "old-0", "new-0")
SAVED_VERSION_BOOTSTRAPS = ("engine_bootstrap.py", "config_edit_bootstrap.py", "github_connection_bootstrap.py",
    "environment_bootstrap.py", "offline_preflight_bootstrap.py", "android_build_bootstrap.py",
    "project_recovery_bootstrap.py", "github_preflight_bootstrap.py", "ios_archive_bootstrap.py", "github_release_bootstrap.py", "artifact_inspection_bootstrap.py", "github_setup_bootstrap.py", "github_history_bootstrap.py")


def saved_version_facts(value):
    return (*full9(value), getattr(value, "st_flags", 0))


def saved_version_same_move(before, after):
    # Only the actual version old->backup / backup->public rename can change ctime.
    return before[:8] == after[:8] and before[9:] == after[9:]


def saved_version_payload(body):
    import base64
    spec = document(body)
    paths = {SAVED_VERSION_PATH, "project/release/mobile-release.json", "project/.gitignore",
        "project/README-user.txt", "project/.github/workflows/keep-user.yml", "sources/01.png", "sources/02.png"}
    paths.update("project/release/store/android/" + locale + "/" + leaf
                 for locale in ("en-US", "fr-FR") for leaf in ("title.txt", "short_description.txt", "full_description.txt"))
    need(set(spec) == {"schemaVersion", "files", "stages", "templateDataSHA256"}
         and type(spec["schemaVersion"]) is int and spec["schemaVersion"] == 1
         and type(spec["files"]) is dict and set(spec["files"]) == paths
         and type(spec["stages"]) is dict and set(spec["stages"]) == {"config", "workflows", "text", "version", "images"},
         "saved-version-fixed-data")
    def decode(raw):
        need(type(raw) is str, "saved-version-data-encoding")
        value = base64.b64decode(raw, validate=True)
        need(len(value) <= 32768, "saved-version-data-leaf-bound")
        return value
    files = {name: decode(raw) for name, raw in spec["files"].items()}
    need(set(spec["stages"]["config"]) == {"project/release/mobile-release.json", "project/.gitignore"}
         and set(spec["stages"]["version"]) == {SAVED_VERSION_PATH}, "saved-version-fixed-stage")
    files["project/.gitignore"] = decode(spec["stages"]["config"]["project/.gitignore"])
    after = decode(spec["stages"]["version"][SAVED_VERSION_PATH])
    need(sum(map(len, files.values())) + len(after) <= 256 * 1024, "saved-version-data-total")
    return files, after


def saved_version_producer_frames(body):
    need(type(body) is bytes and 0 < len(body) <= 65536 and body.endswith(b"\n"), "saved-version-producer-output")
    lines = body.splitlines()
    need(len(lines) == 2, "saved-version-producer-two-frames")
    frames = [document(line) for line in lines]
    for sequence, (frame, kind) in enumerate(zip(frames, ("opened", "prepared"))):
        need(set(frame) == {"protocol", "session", "seq", "kind", "result"}
             and frame["protocol"] == "mrk-release-version/1"
             and frame["session"] == "0123456789abcdef0123456789abcdef"
             and type(frame["seq"]) is int and frame["seq"] == sequence and frame["kind"] == kind
             and type(frame["result"]) is dict and frame["result"].get("scopeResources") == "settled",
             "saved-version-producer-frame")
    need(frames[0]["result"].get("source") == "release/version.properties"
         and frames[0]["result"].get("values") == {"name": "1.2.3", "build": "7"}
         and type(frames[1]["result"].get("view")) is dict, "saved-version-producer-original-checkout")
    return sha(body)


def normal_saved_version_markers(stdout):
    need(type(stdout) is bytes and 0 < len(stdout) <= 1024 * 1024 and stdout.endswith(b"\n"),
         "saved-version-ui-output")
    lines = stdout.decode("utf-8", "strict").splitlines()
    selected = "-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectSavedVersionRecovery]"
    events = [line for line in lines if line.startswith("Test Case ")]
    need(len(events) == 2 and events[0] == "Test Case '" + selected + "' started."
         and re.fullmatch(r"Test Case '" + re.escape(selected) + r"' passed \([0-9]+(?:\.[0-9]+)? seconds\)\.", events[1])
         and lines.count(ORIGINAL_MARKER) == lines.count(SAVED_VERSION_MARKER) == 1
         and sum(line.startswith("MRK_MACOS_UI_ORIGINAL=") for line in lines) == 1
         and sum(line.startswith("MRK_MACOS_NORMAL_SAVED_VERSION_RECOVERY_UI=") for line in lines) == 1
         and not any(line.startswith("MRK_MACOS_UI_FAILURE_CLEANUP=") for line in lines)
         and lines.index(events[0]) < lines.index(ORIGINAL_MARKER) < lines.index(SAVED_VERSION_MARKER) < lines.index(events[1]),
         "saved-version-ui-one-original-terminal")
    return True


class SavedVersionFixture:
    """Retained fixed SOURCE/fixture originals, borrowed by exactly one XCTest.

    SOURCE is checked against the same Git commit and current runtime S; it is
    not a serialized previous core lease. The fresh app registers its own root.
    """
    def __init__(self, phase, source, normal):
        self.phase, self.source, self.normal = phase, source, Path(normal)
        self.fds, self.sources, self.source_dirs, self.dirs = [], {}, {}, {}
        self.root = None
        self.originals, self.seed = {}, {}
        self.handoff = self.normal / "saved-version-recovery-fixture.json"
        self.handoff_original = None
        self.receipt = None

    def _adopt(self, fd):
        self.fds.append(fd)
        return fd

    def _read(self, parent, name, limit):
        fd = self._adopt(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent))
        facts = saved_version_facts(os.fstat(fd))
        body, _, digest = original_body(fd, limit, collect=True)
        need(facts == saved_version_facts(os.fstat(fd))
             == saved_version_facts(os.stat(name, dir_fd=parent, follow_symlinks=False)), "saved-version-file-binding")
        return fd, body, facts, digest

    def _source_directory(self, name):
        if name not in self.source_dirs:
            path = self.phase.root / name
            fd = self._adopt(open_directory(path))
            self.source_dirs[name] = (fd, saved_version_facts(os.fstat(fd)))
        return self.source_dirs[name][0]

    def _sources(self):
        fixed = {"desktop/" + name for name in SAVED_VERSION_BOOTSTRAPS}
        fixed.update(("desktop/cpython-source-inputs/github-ca.pem", "desktop/tools/prepare_runtime.py"))
        selected = sorted(fixed | {"src/mobile_release", SAVED_VERSION_PRODUCER, SAVED_VERSION_DATA})
        args = ["/usr/bin/git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                "ls-tree", "-r", "-z", "--full-tree", self.source, "--", *selected]
        original = self.phase.call("saved-version-source-roster", args, 15, 65536)
        need(original.returncode == 0 and original.stderr == b"" and original.stdout.endswith(b"\0"), "saved-version-source-query")
        rows = original.stdout[:-1].split(b"\0")
        need(0 < len(rows) <= 256, "saved-version-source-count")
        core, total = {}, 0
        for row in rows:
            header, raw = row.split(b"\t", 1)
            mode, kind, blob = header.split(b" ")
            name = raw.decode("ascii", "strict")
            is_core = name.startswith("src/mobile_release/")
            need(mode in (b"100644", b"100755") and kind == b"blob" and re.fullmatch(rb"[0-9a-f]{40}", blob)
                 and all(part not in ("", ".", "..") for part in name.split("/")) and name not in self.sources
                 and (name in fixed or name in (SAVED_VERSION_PRODUCER, SAVED_VERSION_DATA)
                      or is_core and Path(name).suffix in (".py", ".json", ".pem")), "saved-version-source-row")
            parent = self._source_directory(str(Path(name).parent))
            entry = self._read(parent, Path(name).name, 1024 * 1024)
            _, body, facts, digest = entry
            total += len(body)
            need(total <= 32 * 1024 * 1024 and hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest() == blob.decode()
                 and not facts[2] & 0o022, "saved-version-source-bytes")
            self.sources[name] = entry
            if is_core or name in fixed:
                core[name] = {"path": name, "size": len(body), "sha256": digest}
        need(fixed | {SAVED_VERSION_PRODUCER, SAVED_VERSION_DATA, "src/mobile_release/__init__.py"} <= self.sources.keys()
             and sha(encoded([core[name] for name in sorted(core)])) == SAVED_VERSION_SOURCE, "saved-version-current-s")
        # No untracked Python or bytecode can be imported instead of the checked
        # source. Only this package subtree is closed; unrelated repo files stay out.
        names = {name for name in self.sources if name.startswith("src/mobile_release/")}
        directories = {"src/mobile_release"}
        for name in names:
            directories.update(str(parent) for parent in Path(name).parents if str(parent).startswith("src/mobile_release"))
        for name in sorted(directories):
            fd = self._source_directory(name)
            expected = {Path(item).name for item in names | directories if str(Path(item).parent) == name}
            need(set(os.listdir(fd)) == expected, "saved-version-no-shadow-imports")
        self.core_names, self.core_dirs = names, directories
        runtime_parent = self._adopt(open_directory(self.normal.parent))
        self.runtime = self._read(runtime_parent, "runtime-result.json", 65536)
        runtime = document(self.runtime[1])
        need(runtime.get("sourceInputsSha256") == SAVED_VERSION_SOURCE and runtime.get("sourceInputCount") == len(core)
             and runtime.get("target") == self.phase_target
             and runtime.get("qualification") == "current-source-staged-no-native-execution"
             and type(runtime.get("successorManifestSha256")) is str
             and re.fullmatch(r"[0-9a-f]{64}", runtime["successorManifestSha256"]), "saved-version-runtime-source-binding")
        self.runtime_parent = runtime_parent
        self.runtime_manifest = runtime["successorManifestSha256"]
        self.source_digest = sha(encoded({name: [decimal(entry[2]), entry[3]] for name, entry in sorted(self.sources.items())}))
        self.check_sources()

    def check_sources(self):
        for name, (fd, before) in self.source_dirs.items():
            need(saved_version_facts(os.fstat(fd)) == before
                 and saved_version_facts(os.stat(self.phase.root / name, follow_symlinks=False)) == before, "saved-version-source-directory-post")
            if name in self.core_dirs:
                expected = {Path(item).name for item in self.core_names | self.core_dirs if str(Path(item).parent) == name}
                need(set(os.listdir(fd)) == expected, "saved-version-source-roster-post")
        for name, (fd, body, facts, digest) in self.sources.items():
            parent = self.source_dirs[str(Path(name).parent)][0]
            actual, _, actual_digest = original_body(fd, 1024 * 1024, collect=True)
            need(actual == body and actual_digest == digest and saved_version_facts(os.fstat(fd)) == facts
                 and saved_version_facts(os.stat(Path(name).name, dir_fd=parent, follow_symlinks=False)) == facts, "saved-version-source-post")
        fd, body, facts, digest = self.runtime
        actual, _, actual_digest = original_body(fd, 65536, collect=True)
        need(actual == body and actual_digest == digest and saved_version_facts(os.fstat(fd)) == facts
             and saved_version_facts(os.stat("runtime-result.json", dir_fd=self.runtime_parent, follow_symlinks=False)) == facts,
             "saved-version-runtime-post")

    def _directory(self, path, parent, name):
        fd = self._adopt(os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent))
        facts = saved_version_facts(os.fstat(fd))
        need(facts == saved_version_facts(os.stat(name, dir_fd=parent, follow_symlinks=False))
             and facts[2] == stat.S_IFDIR | 0o700 and facts[3:5] == (os.getuid(), os.getgid()) and facts[9] == 0,
             "saved-version-private-directory")
        self.dirs[path] = (fd, parent, name, facts)
        return fd

    def _leaf(self, path):
        parent, name = posixpath.split(path)
        entry = self._read(self.dirs[parent][0], name, 32768)
        mode = 0o644 if path.startswith("sources/") else 0o600
        need(entry[2][2] == stat.S_IFREG | mode and entry[2][3:5] == (os.getuid(), os.getgid())
             and entry[2][9] == 0 and entry[2][0] == self.dirs[""][3][0], "saved-version-private-file")
        return entry

    def _recheck_leaf(self, path, entry):
        # Same unchanged original descriptor and exact named location, never a
        # replacement authority or a second retained copy of its observation.
        parent, name = posixpath.split(path)
        fd, body, facts, digest = entry
        parent_fd = self.dirs[parent][0]
        need(saved_version_facts(os.fstat(fd)) == facts
             and saved_version_facts(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) == facts,
             "saved-version-reused-original-pre")
        observed, _, found = original_body(fd, 32768, collect=True)
        need(observed == body and found == digest and saved_version_facts(os.fstat(fd)) == facts
             and saved_version_facts(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) == facts,
             "saved-version-reused-original-post")
        return entry

    def check_roster(self, paths, *, moved=False):
        directories = {""}
        for path in paths:
            directories.update(str(parent) for parent in Path(path).parents if str(parent) != ".")
        need(set(self.dirs) == directories, "saved-version-directory-roster")
        for path, (fd, parent, name, before) in self.dirs.items():
            actual = saved_version_facts(os.fstat(fd))
            need(actual == saved_version_facts(os.stat(name, dir_fd=parent, follow_symlinks=False)), "saved-version-directory-binding")
            if moved and path in ("project", "project/release"):
                need(before[:5] == actual[:5] and before[9:] == actual[9:], "saved-version-owned-directory-transition")
            else:
                need(before == actual, "saved-version-directory-facts")
            expected = {Path(item).name for item in set(paths) | directories if item and posixpath.dirname(item) == path}
            need(set(os.listdir(fd)) == expected and saved_version_facts(os.fstat(fd)) == actual, "saved-version-exact-roster")
        need(saved_version_facts(os.fstat(self.temporary)) == saved_version_facts(os.stat(SAVED_VERSION_TEMPORARY, follow_symlinks=False)),
             "saved-version-temporary-binding")

    def _stage(self):
        import tempfile
        self.files, self.after = saved_version_payload(self.sources[SAVED_VERSION_DATA][1])
        self.temporary = self._adopt(open_directory(SAVED_VERSION_TEMPORARY))
        self.root = Path(tempfile.mkdtemp(prefix="mrk-normal-project-", dir=SAVED_VERSION_TEMPORARY))
        need(self.root.parent == SAVED_VERSION_TEMPORARY and re.fullmatch(r"mrk-normal-project-[A-Za-z0-9_-]{6,16}", self.root.name), "saved-version-fresh-root")
        self._directory("", self.temporary, self.root.name)
        directories = set()
        for path in self.files:
            directories.update(str(parent) for parent in Path(path).parents if str(parent) != ".")
        for path in sorted(directories, key=lambda value: (value.count("/"), value)):
            parent, name = posixpath.split(path)
            os.mkdir(name, 0o700, dir_fd=self.dirs[parent][0])
            self._directory(path, self.dirs[parent][0], name)
        for path, body in sorted(self.files.items()):
            parent, name = posixpath.split(path)
            parent_fd = self.dirs[parent][0]
            mode = 0o644 if path.startswith("sources/") else 0o600
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent_fd)
            try:
                os.fchmod(fd, mode)  # Only this new fixture leaf, never a user file.
                offset = 0
                while offset < len(body):
                    count = os.write(fd, body[offset:]); need(0 < count <= len(body) - offset, "saved-version-fixture-write")
                    offset += count
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(parent_fd)
            self.originals[path] = self._leaf(path)
            need(self.originals[path][1] == body, "saved-version-fixture-readback")
        # Capture only after all explicit creation, including the derived ignore bytes.
        self.dirs = {path: (fd, parent, name, saved_version_facts(os.fstat(fd)))
                     for path, (fd, parent, name, _) in self.dirs.items()}
        self.check_roster(self.originals)

    def interrupt(self, target):
        self.phase_target = target
        need(sys.flags.isolated == 1 and sys.flags.no_site == 1 and sys.flags.dont_write_bytecode == 1
             and Path(sys.executable).is_absolute() and SAVED_VERSION_ENV not in self.phase.environment,
             "saved-version-admitted-interpreter-environment")
        self._sources(); self._stage(); self.check_sources()
        original = self.phase.call("saved-version-core-interrupt", [sys.executable, "-I", "-S", "-B",
            str(self.phase.root / SAVED_VERSION_PRODUCER), "--restart-child", str(self.root / "project"),
            "release_version", "interrupt"], 20, 65536)
        need(original.returncode == 86 and original.stderr == b"", "saved-version-original-interrupt86")
        frames_digest = saved_version_producer_frames(original.stdout)
        self.check_sources()
        self._directory(SAVED_VERSION_JOURNAL, self.dirs["project"][0], ".mobile-release-version")
        paths = set(self.originals) - {SAVED_VERSION_PATH}
        paths.update(SAVED_VERSION_JOURNAL + "/" + name for name in SAVED_VERSION_CONTROLS)
        for path in sorted(paths):
            entry = (self._recheck_leaf(path, self.originals[path]) if path in self.originals
                     else self._leaf(path))
            self.seed[path] = entry
        backup = self.seed[SAVED_VERSION_JOURNAL + "/old-0"]
        need(backup[1] == self.files[SAVED_VERSION_PATH]
             and saved_version_same_move(self.originals[SAVED_VERSION_PATH][2], backup[2])
             and self.seed[SAVED_VERSION_JOURNAL + "/new-0"][1] == self.after, "saved-version-actual-rename-state")
        header = document(self.seed[SAVED_VERSION_JOURNAL + "/header.json"][1])
        plan = document(self.seed[SAVED_VERSION_JOURNAL + "/plan.json"][1])
        need(header.get("schemaVersion") == 2 and header.get("domain") == "release_version"
             and type(header.get("transactionId")) is str and re.fullmatch(r"[0-9a-f]{32}", header["transactionId"])
             and plan.get("transactionId") == header["transactionId"] and type(plan.get("files")) is list
             and len(plan["files"]) == 1 and plan["files"][0].get("path") == "release/version.properties",
             "saved-version-actual-ready-journal")
        self.check_roster(paths, moved=True)
        self.dirs = {path: (fd, parent, name, saved_version_facts(os.fstat(fd)))
                     for path, (fd, parent, name, _) in self.dirs.items()}
        self.check_roster(paths)
        handoff = {"schemaVersion": 1, "scope": "one-owned-saved-version-recovery-fixture", "sourceCommit": self.source,
            "sourceInputsSha256": SAVED_VERSION_SOURCE, "runtimeManifestSha256": self.runtime_manifest,
            "sourceClosureSha256": self.source_digest, "fixtureDataSha256": self.sources[SAVED_VERSION_DATA][3],
            "producerSha256": self.sources[SAVED_VERSION_PRODUCER][3], "producerFramesSha256": frames_digest,
            "root": str(self.root), "transactionId": header["transactionId"],
            "originalVersionFacts": decimal(self.originals[SAVED_VERSION_PATH][2]),
            "directories": {name: decimal(row[3]) for name, row in sorted(self.dirs.items())},
            "files": {name: {"facts": decimal(row[2]), "sha256": row[3]} for name, row in sorted(self.seed.items())}}
        exclusive_output(self.handoff, encoded(handoff) + b"\n", 16384)
        parent = self._adopt(open_directory(self.normal))
        self.handoff_original = (parent, self._read(parent, self.handoff.name, 16384))
        self.receipt = {name: handoff[name] for name in ("sourceInputsSha256", "runtimeManifestSha256", "sourceClosureSha256",
            "fixtureDataSha256", "producerSha256", "producerFramesSha256")}
        self.receipt.update(runtimeResultSha256=self.runtime[3], handoffSha256=sha(encoded(handoff) + b"\n"), producerReturncode=86,
            publicOriginalCount=13, readyJournalFileCount=6, interruptedGuiSaveObserved=False)

    def ui_call(self, role, argv, seconds, limit=1024 * 1024):
        need(self.handoff_original is not None, "saved-version-handoff-not-published")
        self.check_sources()
        if role != "one-admitted-ui-test":
            return self.phase.call(role, argv, seconds, limit)
        self.check_seed()
        old = self.phase.environment
        try:
            self.phase.environment = dict(old, **{SAVED_VERSION_ENV: str(self.handoff)})
            return self.phase.call(role, argv, seconds, limit)
        finally:
            self.phase.environment = old

    def check_seed(self):
        self.check_roster(self.seed)
        for path, (fd, body, facts, digest) in self.seed.items():
            parent, name = posixpath.split(path)
            actual, _, found = original_body(fd, 32768, collect=True)
            need(actual == body and found == digest and saved_version_facts(os.fstat(fd)) == facts
                 and saved_version_facts(os.stat(name, dir_fd=self.dirs[parent][0], follow_symlinks=False)) == facts,
                 "saved-version-seed-changed-before-ui")
        parent, (fd, body, facts, digest) = self.handoff_original
        actual, _, found = original_body(fd, 16384, collect=True)
        need(actual == body and found == digest and saved_version_facts(os.fstat(fd)) == facts
             and saved_version_facts(os.stat(self.handoff.name, dir_fd=parent, follow_symlinks=False)) == facts,
             "saved-version-handoff-changed-before-ui")

    def restored(self):
        normal_saved_version_markers(self.original.stdout)
        expected = {}
        for path in sorted(self.originals):
            observed = (self._leaf(path) if path == SAVED_VERSION_PATH
                        else self._recheck_leaf(path, self.originals[path]))
            if path == SAVED_VERSION_PATH:
                backup = self.seed[SAVED_VERSION_JOURNAL + "/old-0"]
                need(observed[1] == self.files[path] and saved_version_same_move(backup[2], observed[2]), "saved-version-restored-original")
            else:
                need(observed[1:] == self.originals[path][1:], "saved-version-restored-unrelated-original")
            expected[path] = observed
        # The held journal may now be unlinked. Remove only its roster entry,
        # never the original FD or any filesystem object; close consumes it later.
        self.dirs.pop(SAVED_VERSION_JOURNAL)
        self.check_roster(expected, moved=True)
        self.check_sources()
        parent, (fd, body, facts, digest) = self.handoff_original
        observed, _, found = original_body(fd, 16384, collect=True)
        need(observed == body and found == digest and saved_version_facts(os.fstat(fd)) == facts
             and saved_version_facts(os.stat(self.handoff.name, dir_fd=parent, follow_symlinks=False)) == facts,
             "saved-version-handoff-post")
        self.receipt.update(originalFixtureRestored=True, unrelatedOriginalsUnchanged=True, readyJournalRemoved=True,
            sourcePrePostMatched=True, uiOriginalMarkersObserved=True)
        return self.receipt

    def close(self):
        failure = None
        while self.fds:
            fd = self.fds.pop()
            try:
                os.close(fd)
            except BaseException as error:
                if failure is None: failure = error
        if failure is not None: raise failure

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        try:
            self.close()
        except BaseException:
            if kind is None: raise
        return False


class NativeQueryFailure(Exception):
    """One validated returned nonzero query; no later build/query is dispatched."""
    def __init__(self, original):
        super().__init__("normal-toolchain-original-nonzero")
        self.original = original


# One fixed filesystem DATA case, deliberately outside ordinary UI selections.
OUTPUT_DATA_METHOD = CLASS + "testPositiveAndroidOutputCustodyData"
OUTPUT_DATA_RESULT = "output-data-test.xcresult"
OUTPUT_DATA_SCOPE = "external-xctest-output-filesystem-data-only"


def output_data_clock(value, seconds):
    need(type(value) is dict and set(value) == {"startNs", "deadlineNs", "beforePublicationNs", "postCloseDeadlineRequired"}
         and value["postCloseDeadlineRequired"] is True, "output-data-clock")
    need(all(type(value[key]) is str and re.fullmatch(r"[0-9]{1,20}", value[key])
             for key in ("startNs", "deadlineNs", "beforePublicationNs")), "output-data-clock-values")
    need(int(value["startNs"]) <= int(value["beforePublicationNs"]) < int(value["deadlineNs"])
         and int(value["deadlineNs"]) - int(value["startNs"]) == seconds * 10**9, "output-data-clock-bound")


def output_data_records(commands, expected):
    need(type(commands) is list and len(commands) == len(expected), "output-data-command-count")
    for row, (role, cap, limit, argv) in zip(commands, expected, strict=True):
        need(type(row) is dict and set(row) == {"role", "returncode", "timeoutSeconds", "roleCapSeconds",
            "outputLimitBytes", "argvSha256", "stdoutBytes", "stdoutSha256", "stderrBytes", "stderrSha256"}, "output-data-command-fields")
        need(row["role"] == role and type(row["returncode"]) is int and row["returncode"] == 0
             and type(row["timeoutSeconds"]) is int and 1 <= row["timeoutSeconds"] <= cap
             and type(row["roleCapSeconds"]) is int and row["roleCapSeconds"] == cap
             and type(row["outputLimitBytes"]) is int and row["outputLimitBytes"] == limit, "output-data-command-values")
        need(all(type(row[key]) is int and 0 <= row[key] <= limit for key in ("stdoutBytes", "stderrBytes"))
             and row["stdoutBytes"] + row["stderrBytes"] <= limit
             and all(type(row[key]) is str and re.fullmatch(r"[0-9a-f]{64}", row[key])
                     for key in ("argvSha256", "stdoutSha256", "stderrSha256"))
             and row["argvSha256"] == sha(encoded(argv)), "output-data-command-original")
    need(commands[0]["stdoutSha256"] == commands[-1]["stdoutSha256"], "output-data-source-command-post")


def output_data_source_argv(source):
    return ["/usr/bin/git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
        "ls-tree", "-r", "-z", "--full-tree", source, "--", "desktop/native/macos-normal-ui",
        "desktop/tools/macos_normal_ui_runner.py"]


def output_data_build_receipt(value, source, normal, roster):
    expected = dict(schemaVersion=1, scope="normal-ui-original-command-admission-only", phase="build",
        resultBundle=None, originalCommandRole="normal-ui-build", originalReturncode=0,
        target=ARM_TARGET, sourceCommit=source, sourceRosterSha256=roster, sourcePrePostMatched=True,
        originalCommandReturned=True, fileLimitBytes=[32 * 1024**3] * 2,
        receiptPolicy="exclusive0600-readback-consuming-close")
    need(type(value) is dict and set(value) == set(expected) | {"commands", "phaseClock"}, "output-data-build-fields")
    need(all(type(value[key]) is type(wanted) and value[key] == wanted for key, wanted in expected.items()), "output-data-build-values")
    output_data_clock(value["phaseClock"], 450)
    source_command = ("normal-ui-source-roster", 15, 1048576, output_data_source_argv(source))
    commands = [source_command, *[("normal-toolchain-" + key, 15, 4096, list(argv)) for key, _, argv in TOOLCHAIN_QUERIES],
                ("normal-ui-build", 240, 1048576, normal_build_arguments(normal / "DerivedData")), source_command]
    output_data_records(value["commands"], commands)


def output_data_success_receipt(value, source, normal, build_raw):
    """Fixed success DATA only; actual wrapper zero is a separate workflow gate."""
    build = document(build_raw)
    roster = build.get("sourceRosterSha256")
    need(type(roster) is str and re.fullmatch(r"[0-9a-f]{64}", roster), "output-data-build-roster")
    output_data_build_receipt(build, source, normal, roster)
    expected = dict(schemaVersion=1, scope=OUTPUT_DATA_SCOPE, phase="output-data", resultBundle=OUTPUT_DATA_RESULT,
        originalCommandRole="one-admitted-ui-test", originalReturncode=0, target=ARM_TARGET, sourceCommit=source,
        sourceRosterSha256=roster, sourcePrePostMatched=True, originalCommandReturned=True,
        buildReceiptSha256=sha(build_raw), fileLimitBytes=[1024**3] * 2,
        receiptPolicy="exclusive0600-readback-consuming-close")
    need(type(value) is dict and set(value) == set(expected) | {"runnerAdmission", "observation", "commands", "phaseClock"},
         "output-data-success-fields")
    need(all(type(value[key]) is type(wanted) and value[key] == wanted for key, wanted in expected.items()),
         "output-data-success-values")
    output_data_clock(value["phaseClock"], 345)
    runner = value["runnerAdmission"]
    fixed = dict(schemaVersion=1, scope="actual-generated-xctrunner-admission-only",
        runnerPath=str(normal / "DerivedData/Build/Products" / RUNNER), strictCodesignOriginalZero=True,
        reSignedOrRepaired=False, originalProductsPrePostMatched=True, originalClosesCompleted=True)
    need(type(runner) is dict and set(runner) == set(fixed) | {"xctestrunPath", "runnerExecutable", "testExecutable", "xctestrun",
         "productEntryCount", "productRosterSha256", "entitlementsSha256", "appSandboxEntitlement"}, "output-data-runner-fields")
    need(all(type(runner[key]) is type(wanted) and runner[key] == wanted for key, wanted in fixed.items())
         and type(runner["appSandboxEntitlement"]) is str and runner["appSandboxEntitlement"] in ("absent", "false")
         and type(runner["productEntryCount"]) is int and 5 <= runner["productEntryCount"] <= 4096,
         "output-data-runner-values")
    manifest = runner["xctestrunPath"]
    need(type(manifest) is str and len(manifest) <= 2048
         and Path(manifest).parent == normal / "DerivedData/Build/Products"
         and re.fullmatch(r"MRKNormalAppUI_macosx[0-9A-Za-z_.-]+\.xctestrun", Path(manifest).name), "output-data-manifest")
    for key in ("runnerExecutable", "testExecutable", "xctestrun"):
        row = runner[key]
        need(type(row) is list and len(row) == 3 and row[0] == "file" and type(row[1]) is list and len(row[1]) == 9
             and all(type(part) is str and re.fullmatch(r"[0-9]{1,20}", part) for part in row[1])
             and stat.S_ISREG(int(row[1][2])) and int(row[1][5]) == 1 and 0 < int(row[1][6]) <= 256 * 1024**2
             and type(row[2]) is str and re.fullmatch(r"[0-9a-f]{64}", row[2]), "output-data-runner-original-row")
    need(all(type(runner[key]) is str and re.fullmatch(r"[0-9a-f]{64}", runner[key])
             for key in ("productRosterSha256", "entitlementsSha256")), "output-data-runner-digest")
    observation = value["observation"]
    fixed_observation = dict(testIdentifier=OUTPUT_DATA_METHOD,
        testCounts={"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0},
        oneOriginalAttemptObserved=True, productReady=False)
    need(type(observation) is dict and set(observation) == set(fixed_observation) | {"nativeSummarySha256", "nativeTestTreeSha256"}
         and encoded({key: observation[key] for key in fixed_observation}) == encoded(fixed_observation)
         and all(type(observation[key]) is str and re.fullmatch(r"[0-9a-f]{64}", observation[key])
                 for key in ("nativeSummarySha256", "nativeTestTreeSha256")), "output-data-observation")
    source_command = ("normal-ui-source-roster", 15, 1048576, output_data_source_argv(source))
    query = ["/usr/bin/xcrun", "xcresulttool", "get", "test-results"]
    tail = ["--path", str(normal / OUTPUT_DATA_RESULT), "--compact"]
    expected_commands = [source_command,
        ("verify-generated-runner", 30, 1048576, ["/usr/bin/codesign", "--verify", "--strict", runner["runnerPath"]]),
        ("generated-runner-entitlements", 30, 1048576, ["/usr/bin/codesign", "-d", "--entitlements", ":-", runner["runnerPath"]]),
        ("one-admitted-ui-test", 120, 1048576, xcode_test_arguments(manifest, normal / OUTPUT_DATA_RESULT,
            (OUTPUT_DATA_METHOD,), 60, output_data=True)),
        ("normal-ui-summary", 30, 262144, query + ["summary"] + tail),
        ("normal-ui-test-tree", 30, 262144, query + ["tests"] + tail), source_command]
    output_data_records(value["commands"], expected_commands)
    need(value["commands"][0]["stdoutSha256"] == build["commands"][0]["stdoutSha256"]
         and value["commands"][4]["stdoutSha256"] == observation["nativeSummarySha256"]
         and value["commands"][5]["stdoutSha256"] == observation["nativeTestTreeSha256"]
         and value["commands"][2]["stdoutSha256"] == runner["entitlementsSha256"], "output-data-original-digest-joins")


def output_data_read_build(phase, normal, source, roster):
    parent = open_directory(normal)
    fd = None
    primary = None
    result = None
    try:
        parent_identity = full9(os.fstat(parent))[:5]
        need(parent_identity[3:] == (os.getuid(), os.getgid()) and stat.S_IMODE(parent_identity[2]) == 0o700,
             "output-data-private-parent")
        fd = os.open("build.command-admission.json", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        raw, facts, digest = original_body(fd, 32768, collect=True)
        need(facts[3:5] == (os.getuid(), os.getgid()) and stat.S_IMODE(facts[2]) == 0o600
             and full9(os.stat("build.command-admission.json", dir_fd=parent, follow_symlinks=False)) == facts,
             "output-data-build-original")
        output_data_build_receipt(document(raw), source, normal, roster)
        need(full9(os.stat(normal, follow_symlinks=False))[:5] == parent_identity
             and full9(os.fstat(parent))[:5] == parent_identity, "output-data-private-parent-post")
        result = digest
    except BaseException as error:
        primary = error
    finally:
        for original in (fd, parent):
            if original is not None:
                try:
                    os.close(original)
                except BaseException as error:
                    if primary is None:
                        primary = error
        try:
            phase.clock.check()
        except BaseException as error:
            if primary is None:
                primary = error
    if primary is not None:
        raise primary
    return result


def output_data_result(stdout, summary_body, tests_body):
    need(type(stdout) is bytes and 0 < len(stdout) <= 1048576
         and type(summary_body) is bytes and 0 < len(summary_body) <= 262144
         and type(tests_body) is bytes and 0 < len(tests_body) <= 262144, "output-data-result-bound")
    text = stdout.decode("utf-8", "strict")
    lines = text.splitlines()
    selected = "-[MRKNormalAppUITests.NormalAppUITests testPositiveAndroidOutputCustodyData]"
    attempts = [line for line in lines if line.startswith("Test Case ")]
    need(len(attempts) == 2 and attempts[0] == "Test Case '" + selected + "' started."
         and re.fullmatch(r"Test Case '" + re.escape(selected) + r"' passed \([0-9]+(?:\.[0-9]+)? seconds\)\.", attempts[1]),
         "output-data-one-original-attempt")
    need("MRK_MACOS_UI_ORIGINAL=" not in text and "MRK_MACOS_UI_FAILURE_CLEANUP=" not in text,
         "output-data-not-product-ui")
    summary = document(summary_body)
    counts = {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0}
    need(all(type(summary.get(key)) is int and summary[key] == count for key, count in counts.items()), "output-data-exact-one-pass")
    roots = document(tests_body).get("testNodes")
    need(type(roots) is list and 0 < len(roots) <= 16, "output-data-tree-root")
    pending, visited, cases = [(node, (), 0) for node in roots], 0, 0
    while pending:
        node, ancestors, depth = pending.pop()
        visited += 1
        need(type(node) is dict and visited <= 128 and depth <= 12, "output-data-tree-bound")
        name, kind, children = node.get("name"), node.get("nodeType"), node.get("children", [])
        need(type(name) is str and type(kind) is str and type(children) is list and len(children) <= 16, "output-data-tree-node")
        if kind == "Test Case":
            need(TARGET in ancestors and node.get("result") == "Passed" and not children
                 and name == "testPositiveAndroidOutputCustodyData()"
                 and node.get("nodeIdentifier") in {"NormalAppUITests/testPositiveAndroidOutputCustodyData()", OUTPUT_DATA_METHOD + "()"},
                 "output-data-exact-selected-case")
            cases += 1
        else:
            pending.extend((child, ancestors + (name,), depth + 1) for child in children)
    need(cases == 1, "output-data-tree-one-case")
    return {"testIdentifier": OUTPUT_DATA_METHOD, "testCounts": counts,
        "nativeSummarySha256": sha(summary_body), "nativeTestTreeSha256": sha(tests_body),
        "oneOriginalAttemptObserved": True, "productReady": False}


def output_data_result_post_masks(query, before, held, named):
    """Changed-component booleans only, in full9 order; no raw identity values."""
    return dict(schemaVersion=1, query=query, originalReturncode=0,
        heldVsPre=[a != b for a, b in zip(held, before, strict=True)],
        namedVsPre=[a != b for a, b in zip(named, before, strict=True)],
        heldVsNamed=[a != b for a, b in zip(held, named, strict=True)])


def admit_output_data_result_post(value, records):
    """Optional refusal observation, never permission to adopt changed facts."""
    masks = ("heldVsPre", "namedVsPre", "heldVsNamed")
    need(type(value) is dict and set(value) == {"schemaVersion", "query", "originalReturncode", *masks}
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and type(value["query"]) is str and value["query"] in ("summary", "tests")
         and type(value["originalReturncode"]) is int and value["originalReturncode"] == 0,
         "output-data-post-observation-fields")
    need(all(type(value[key]) is list and len(value[key]) == 9
             and all(type(item) is bool for item in value[key]) for key in masks), "output-data-post-masks")
    # Equality is transitive: exactly one differing pair is impossible. Two
    # changed pairs are valid, including held and named changing to the SAME value.
    need(all(sum(parts) in (0, 2, 3) for parts in zip(*(value[key] for key in masks), strict=True))
         and any(value["heldVsPre"] + value["namedVsPre"]), "output-data-post-mask-consistency")
    role = "normal-ui-summary" if value["query"] == "summary" else "normal-ui-test-tree"
    need(type(records) is list and 0 < len(records) <= 16 and type(records[-1]) is dict
         and records[-1].get("role") == role and type(records[-1].get("returncode")) is int
         and records[-1]["returncode"] == 0, "output-data-post-final-original")
    result = dict(schemaVersion=1, query=value["query"], originalReturncode=0,
                  **{key: list(value[key]) for key in masks})
    need(len(encoded(result)) <= 1024, "output-data-post-observation-bound")
    return result


def execute_output_data_phase(phase, request, source, file_limit):
    need(request["target"] == ARM_TARGET and request["methods"] == (OUTPUT_DATA_METHOD,)
         and request["allowance"] == 60 and request["timeout"] == 120 and request["phaseSeconds"] == 345,
         "output-data-fixed-request")
    normal, result = request["derived"].parent, request["result"]
    before = normal_source_state(phase, source)
    roster = sha(encoded(before))
    build_digest = output_data_read_build(phase, normal, source, roster)
    original, runner = run_admitted_test(phase.call, request["derived"], result, (OUTPUT_DATA_METHOD,), 60, 120,
                                        output_data=True)
    if original.returncode != 0:
        return original  # No success receipt, query, cleanup, or synthetic pass after a failed original.
    result_fd = open_directory(result)
    primary = None
    bodies = []
    failed_query = None
    try:
        result_facts = full9(os.fstat(result_fd))
        need(result_facts[3:5] == (os.getuid(), os.getgid()) and not result_facts[2] & 0o022
             and full9(os.stat(result, follow_symlinks=False)) == result_facts, "output-data-result-original")
        for kind, role in (("summary", "normal-ui-summary"), ("tests", "normal-ui-test-tree")):
            query = phase.call(role, ["/usr/bin/xcrun", "xcresulttool", "get", "test-results", kind,
                                     "--path", str(result), "--compact"], 30, 262144)
            if query.returncode != 0:
                failed_query = query
                break
            held_after = full9(os.fstat(result_fd))
            named_after = full9(os.stat(result, follow_symlinks=False))
            try:
                # This newly generated result is mutable OUTPUT, not immutable
                # SOURCE: a query may change its layout metadata. Keep the
                # original object/type/permissions and live name binding exact.
                need(held_after == named_after and held_after[:5] == result_facts[:5],
                     "output-data-result-post")
            except Refused as error:
                try:
                    error._output_data_result_post = output_data_result_post_masks(
                        kind, result_facts, held_after, named_after)
                except BaseException:
                    pass  # Optional observation cannot replace this exact first refusal.
                raise
            bodies.append(query.stdout)
    except BaseException as error:
        primary = error
    finally:
        try:
            os.close(result_fd)
        except BaseException as error:
            if primary is None:
                primary = error
        try:
            phase.clock.check()
        except BaseException as error:
            if primary is None:
                primary = error
    if primary is not None:
        raise primary
    if failed_query is not None:
        return failed_query
    observation = output_data_result(original.stdout, *bodies)
    need(normal_source_state(phase, source) == before, "output-data-source-pre-post")
    facts = dict(schemaVersion=1, scope=OUTPUT_DATA_SCOPE, phase="output-data", resultBundle=OUTPUT_DATA_RESULT,
        originalCommandRole="one-admitted-ui-test", originalReturncode=0, target=ARM_TARGET, sourceCommit=source,
        sourceRosterSha256=roster, sourcePrePostMatched=True, originalCommandReturned=True,
        buildReceiptSha256=build_digest, runnerAdmission=runner, observation=observation,
        commands=phase.records, fileLimitBytes=list(file_limit), phaseClock=phase.clock.before_publication(),
        receiptPolicy="exclusive0600-readback-consuming-close")
    exclusive_output(normal / "output-data.command-admission.json", encoded(facts) + b"\n", 32768)
    phase.clock.check()
    return original


# Two fixed real-removal UI routes. Not admitted by the ordinary CLI.
REMOVAL_METHODS = {
    "ordinary": "testInstalledRemovalCancelThenContinue",
    "abrupt": "testInstalledRemovalContinueBeforeInterruption",
}
REMOVAL_CHANNEL_ENV = "TEST_RUNNER_MRK_NORMAL_UI_REMOVAL_CHANNEL"


def removal_selection(case):
    need(type(case) is str and case in REMOVAL_METHODS, "removal-fixed-case")
    return CLASS + REMOVAL_METHODS[case], "removal-" + case + "-test.xcresult"


class RemovalPhaseClock(PhaseClock):
    """UI585 is nested in the existing joint deadline; never a new allowance."""
    def __init__(self, containing_deadline_ns, *, now=None, started=None):
        need(type(containing_deadline_ns) is int and containing_deadline_ns > 0,
             "removal-containing-deadline")
        super().__init__(585, now=now, started=started)
        self.containing_deadline_ns = containing_deadline_ns
        self.deadline = min(self.deadline, containing_deadline_ns)
        self.check()


def removal_ui_result(stdout, summary_body, tests_body, case):
    method, _ = removal_selection(case)
    need(type(stdout) is bytes and 0 < len(stdout) <= 1048576
         and type(summary_body) is bytes and 0 < len(summary_body) <= 262144
         and type(tests_body) is bytes and 0 < len(tests_body) <= 262144,
         "removal-ui-result-bound")
    text = stdout.decode("utf-8", "strict")
    lines = text.splitlines()
    marker = ("MRK_MACOS_REMOVAL_UI=v1;case=" + case + ";cancelObserved="
              + ("1" if case == "ordinary" else "0")
              + ";continueObserved=1;originalTerminated=1;gateClosed=1;gateFree=unqualified;normalQuit=0;channelClosed=1")
    need([line for line in lines if line.startswith("MRK_MACOS_REMOVAL_UI=")] == [marker]
         and all(tag not in text for tag in ("MRK_MACOS_UI_ORIGINAL=", "MRK_MACOS_UI_FAILURE_CLEANUP=",
                                            "MRK_MACOS_NORMAL_UI=", "MRK_MACOS_ENTRY_UI=")),
         "removal-ui-distinct-terminal")
    selected = "-[MRKNormalAppUITests.NormalAppUITests " + REMOVAL_METHODS[case] + "]"
    attempts = [line for line in lines if line.startswith("Test Case ")]
    need(len(attempts) == 2 and attempts[0] == "Test Case '" + selected + "' started."
         and re.fullmatch(r"Test Case '" + re.escape(selected) + r"' passed \([0-9]+(?:\.[0-9]+)? seconds\)\.", attempts[1]),
         "removal-ui-one-original-attempt")
    summary = document(summary_body)
    counts = {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0}
    need(all(type(summary.get(key)) is int and summary[key] == count for key, count in counts.items()),
         "removal-ui-exact-one-pass")
    roots = document(tests_body).get("testNodes")
    need(type(roots) is list and 0 < len(roots) <= 16, "removal-ui-tree-root")
    pending, visited, cases = [(node, (), 0) for node in roots], 0, 0
    while pending:
        node, ancestors, depth = pending.pop()
        visited += 1
        need(type(node) is dict and visited <= 128 and depth <= 12, "removal-ui-tree-bound")
        name, kind, children = node.get("name"), node.get("nodeType"), node.get("children", [])
        need(type(name) is str and type(kind) is str and type(children) is list and len(children) <= 16,
             "removal-ui-tree-node")
        if kind == "Test Case":
            need(TARGET in ancestors and node.get("result") == "Passed" and not children
                 and name == REMOVAL_METHODS[case] + "()"
                 and node.get("nodeIdentifier") in {"NormalAppUITests/" + name, method + "()"},
                 "removal-ui-exact-selected-case")
            cases += 1
        else:
            pending.extend((child, ancestors + (name,), depth + 1) for child in children)
    need(cases == 1, "removal-ui-tree-one-case")
    return dict(case=case, testIdentifier=method, testCounts=counts,
        nativeSummarySha256=sha(summary_body), nativeTestTreeSha256=sha(tests_body),
        oneOriginalAttemptObserved=True, originalAppTerminated=True, uiGateClosed=True,
        gateFree="unqualified", normalQuit=False, uiChannelClosed=True, productReady=False)


def removal_phase_context(phase, *, case, derived, channel, source, file_limit, target):
    """Explicit supplied environment; never an os.environ/cwd/loader mutation."""
    method, result_name = removal_selection(case)
    need(type(phase) is NormalPhase and type(phase.clock) is RemovalPhaseClock
         and phase.retain_nonzero is True and not phase.records and target == ARM_TARGET,
         "removal-own-phase")
    need(sys.platform == "darwin" and platform.machine() == "arm64"
         and platform.mac_ver()[0].startswith("26.") and _removal_resource is not None,
         "removal-native-runtime")
    need(file_limit == normal_file_limit("test", _removal_resource.getrlimit(_removal_resource.RLIMIT_FSIZE)),
         "removal-actual-file-limit")
    need(type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source)
         and phase.root == Path("/Users/runner/work/mobile-release-kit/mobile-release-kit"), "removal-source-root")
    need(isinstance(derived, Path) and derived.name == "DerivedData" and derived.parent.name == "normal-ui"
         and derived.parent.parent.parent == Path("/Users/runner/work/_temp")
         and re.fullmatch(r"mrk-macos-installed\.[A-Za-z0-9]{8}", derived.parent.parent.name), "removal-fixed-work")
    need(isinstance(channel, Path) and str(channel) == posixpath.normpath(str(channel))
         and channel.parent == derived.parent.parent / "removal-ui-v1"
         and re.fullmatch(r"r-[0-9a-f]{32}", channel.name) and channel.name != "r-" + "0" * 32
         and len(str(channel).encode("utf-8")) <= 1024, "removal-fixed-channel")
    expected = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/Users/runner", "USER": "runner",
        "LOGNAME": "runner", "TMPDIR": str(derived.parent / "tmp") + "/", "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8", "TZ": "UTC", "DEVELOPER_DIR": DEVELOPER,
        "TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB": "github-hosted-macos26-arm64",
        "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE": source,
        "TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE": source, REMOVAL_CHANNEL_ENV: str(channel)}
    need(type(phase.environment) is dict and phase.environment == expected, "removal-explicit-clean-environment")
    return method, derived.parent / result_name


def execute_removal_ui_phase(phase, *, case, derived, channel, source, file_limit, target=ARM_TARGET):
    need(type(phase) is NormalPhase and type(phase.clock) is RemovalPhaseClock, "removal-own-phase")
    try:
        phase.clock.check()
        return _execute_removal_ui_phase(phase, case=case, derived=derived, channel=channel,
            source=source, file_limit=file_limit, target=target)
    except BaseException:
        phase.clock.failed = True  # Parsing/close/publication failures latch too, not only failed commands.
        raise


def _execute_removal_ui_phase(phase, *, case, derived, channel, source, file_limit, target=ARM_TARGET):
    """One worker's returned originals only. The caller still owes its actual join."""
    method, result = removal_phase_context(phase, case=case, derived=derived, channel=channel,
        source=source, file_limit=file_limit, target=target)
    phase.clock.check()
    before = normal_source_state(phase, source)
    roster = sha(encoded(before))
    build_digest = output_data_read_build(phase, derived.parent, source, roster)
    original, runner = run_admitted_test(phase.call, derived, result, (method,), 300, 420,
                                         target=target, removal_case=case)
    if original.returncode != 0:
        raise NativeQueryFailure(original)  # No query/success receipt after the failed original.
    result_fd = open_directory(result)
    primary, bodies = None, []
    try:
        result_facts = full9(os.fstat(result_fd))
        need(result_facts[3:5] == (os.getuid(), os.getgid()) and not result_facts[2] & 0o022
             and full9(os.stat(result, follow_symlinks=False)) == result_facts, "removal-ui-result-original")
        for kind, role in (("summary", "normal-ui-summary"), ("tests", "normal-ui-test-tree")):
            query = phase.call(role, ["/usr/bin/xcrun", "xcresulttool", "get", "test-results", kind,
                "--path", str(result), "--compact"], 30, 262144)
            if query.returncode != 0:
                raise NativeQueryFailure(query)
            held, named = full9(os.fstat(result_fd)), full9(os.stat(result, follow_symlinks=False))
            # Generated mutable OUTPUT may change layout after a query, not identity/permissions.
            need(held == named and held[:5] == result_facts[:5], "removal-ui-result-post")
            bodies.append(query.stdout)
    except BaseException as error:
        primary = error
    finally:
        try:
            os.close(result_fd)
        except BaseException as error:
            if primary is None:
                primary = error
        try:
            phase.clock.check()
        except BaseException as error:
            if primary is None:
                primary = error
    if primary is not None:
        raise primary
    observation = removal_ui_result(original.stdout, *bodies, case)
    need(normal_source_state(phase, source) == before, "removal-ui-source-pre-post")
    need(file_limit == normal_file_limit("test", _removal_resource.getrlimit(_removal_resource.RLIMIT_FSIZE)),
         "removal-ui-file-limit-post")
    facts = dict(schemaVersion=1, scope="installed-removal-ui-originals-only", case=case,
        resultBundle=result.name, originalCommandRole="one-admitted-ui-test", originalReturncode=0,
        target=target, sourceCommit=source, sourceRosterSha256=roster, sourcePrePostMatched=True,
        originalCommandReturned=True, buildReceiptSha256=build_digest, runnerAdmission=runner,
        observation=observation, commands=phase.records, fileLimitBytes=list(file_limit),
        phaseClock=phase.clock.before_publication(), containingDeadlineNs=str(phase.clock.containing_deadline_ns),
        receiptPolicy="exclusive0600-readback-consuming-close", workerJoin="pending-caller-original-join")
    exclusive_output(result.with_suffix(".runner-admission.json"), encoded(facts) + b"\n", 32768)
    phase.clock.finish()  # Actual receipt close is within the same nonrenewable phase.
    return original, facts


def execute_normal_phase(phase, request, source, file_limit):
    """Original owner/source checks shared by fixed build, test and summary."""
    if request.get("outputData") is True:
        return execute_output_data_phase(phase, request, source, file_limit)
    if request.get("androidPositive") is True:
        return execute_android_signed_phase(phase, request, source, file_limit)
    target = request["target"]
    normal_target_data(target)
    mode, derived, result = request["phase"], request["derived"], request["result"]
    before = normal_source_state(phase, source)
    if mode == "build":
        need(not os.path.lexists(derived), "fresh-derived-data-required")
        values = {}
        for key, name, arguments in TOOLCHAIN_QUERIES:
            original = phase.call("normal-toolchain-" + key, list(arguments), 15, 4096)
            if original.returncode != 0:
                raise NativeQueryFailure(original)
            values[key] = original.stdout
        normal_toolchain(values)
        for key, name, _ in TOOLCHAIN_QUERIES:
            phase.clock.check()
            exclusive_output(derived.parent / name, values[key], 4096)
        original = phase.call("normal-ui-build", normal_build_arguments(derived, target=target), 240)
        facts = {"schemaVersion": 1, "scope": "normal-ui-original-command-admission-only", "phase": "build",
                 "resultBundle": None, "originalCommandRole": "normal-ui-build", "originalReturncode": original.returncode}
        receipt = derived.parent / "build.command-admission.json"
    elif mode == "summary":
        observed = os.stat(result, follow_symlinks=False)
        need(stat.S_ISDIR(observed.st_mode) and observed.st_uid == os.getuid()
             and not observed.st_mode & 0o022, "normal-summary-original-directory")
        arguments = ["/usr/bin/xcrun", "xcresulttool", "get", "test-results", "summary", "--path", str(result), "--compact"]
        original = phase.call("normal-ui-summary", arguments, 30, 262144)
        facts = {"schemaVersion": 1, "scope": "normal-ui-original-command-admission-only", "phase": "summary",
                 "resultBundle": result.name, "originalCommandRole": "normal-ui-summary", "originalReturncode": original.returncode}
        if request.get("iosUnsigned") is True and original.returncode == 0:
            facts["iosUnsignedTestCounts"] = ios_unsigned_summary(original.stdout)
        receipt = result.parent / (SUMMARY_STEMS[result.name] + ".command-admission.json")
    else:
        need(mode == "test", "normal-phase-selection")
        if result.name == SAVED_VERSION_RESULT:
            with SavedVersionFixture(phase, source, derived.parent) as fixture:
                fixture.interrupt(target)
                original, facts = run_admitted_test(fixture.ui_call, derived, result, request["methods"],
                    request["allowance"], request["timeout"], target=target)
                fixture.original = original
                fixture.check_sources()
                if original.returncode == 0:
                    facts["savedVersionRecovery"] = fixture.restored()
            if original.returncode == 0:
                facts["savedVersionRecovery"]["originalClosesCompleted"] = True
        elif request.get("iosUnsigned") is True:
            original, facts = run_admitted_test(phase.call, derived, result, request["methods"],
                request["allowance"], request["timeout"], target=target, ios_unsigned=True)
            if original.returncode == 0:
                facts["iosUnsignedObservation"] = ios_unsigned_marker(original.stdout, source=source)
        else:
            original, facts = run_admitted_test(phase.call, derived, result, request["methods"],
                                                request["allowance"], request["timeout"], target=target)
        facts.update(originalTestReturncode=original.returncode, normalPhase="test", resultBundle=result.name)
        if original.returncode == 0 and result.name == "project-test.xcresult":
            project_markers = normal_project_markers(original.stdout)
            facts["projectFieldAndEditMarkersObserved"] = project_markers
            facts["androidToolSourceBrowseMarkerObserved"] = project_markers
        if original.returncode == 0 and result.name == "workflow-refusal-test.xcresult":
            facts["managedWorkflowRefusalMarkerObserved"] = normal_workflow_refusal_markers(original.stdout)
        if original.returncode == 0 and result.name == "release-evidence-test.xcresult":
            facts["savedReleaseEvidenceMarkerObserved"] = normal_release_evidence_markers(original.stdout)
        receipt = result.with_suffix(".runner-admission.json")
    need(normal_source_state(phase, source) == before, "normal-ui-source-pre-post")
    facts.update(target=target, sourceCommit=source, sourceRosterSha256=sha(encoded(before)), sourcePrePostMatched=True,
                 originalCommandReturned=True, commands=phase.records, fileLimitBytes=list(file_limit),
                 phaseClock=phase.clock.before_publication(), receiptPolicy="exclusive0600-readback-consuming-close")
    exclusive_output(receipt, encoded(facts) + b"\n", 32768)
    phase.clock.check()  # Includes actual original receipt close, never inferred from a persisted flag.
    if request.get("iosUnsigned") is True and mode == "test" and original.returncode == 0:
        exclusive_output(derived.parent / "ios-unsigned-archive.facts.json", encoded(facts["iosUnsignedObservation"]) + b"\n", 16384)
        phase.clock.check()
    return original


def failure_base(phase, selection, original, *, engineering=False):
    # Diagnostic dispatch only: native/ordinary selection admission is unchanged.
    need(type(engineering) is bool and phase in ("build", "test", "summary", "query")
         and (selection is None if phase in ("build", "query") else
              selection == "engineering-test.xcresult" if engineering else selection in NORMAL_SELECTIONS or selection in (OUTPUT_DATA_RESULT, IOS_UNSIGNED_RESULT)),
         "normal-diagnostic-selection")
    cap = 4096 if phase == "query" else 262144 if phase == "summary" else 1024 * 1024
    need(type(original) is subprocess.CompletedProcess and type(original.returncode) is int
         and 1 <= original.returncode <= 255 and type(original.stdout) is bytes and type(original.stderr) is bytes
         and len(original.stdout) + len(original.stderr) <= cap, "normal-diagnostic-original")
    value = {"schemaVersion": 1, "scope": ("engineering-main-ui-failure-diagnostic-only" if engineering
            else "normal-macos-ui-failure-diagnostic-only"), "phase": phase,
        "selection": selection, "originalReturncode": original.returncode,
        "stdoutBytes": len(original.stdout), "stdoutSha256": sha(original.stdout),
        "stderrBytes": len(original.stderr), "stderrSha256": sha(original.stderr),
        "status": "unavailable", "findingsTruncated": False, "errorCodes": [], "sourceFailures": [],
        "queryObservations": [], "requireObservations": [], "dashboardReadiness": None,
        "markers": {"selectedCaseStarted": False, "selectedCaseFailed": False,
            "testExecuteFailed": False, "testingFailed": False, "xcodebuildError": False}}
    if engineering and phase == "test":
        value["engineeringFirstFailure"] = None
    if not engineering and phase == "build":
        value["compilerDiagnostics"] = []
        value["buildFailureReasons"] = []
        value["destinationTable"] = {"state": "unavailable", "unknownRowObserved": False,
            "malformedRowObserved": False, "rowsTruncated": False, "rows": []}
        value["markers"]["buildFailed"] = False
    if not engineering and phase == "test" and selection == OUTPUT_DATA_RESULT:
        value["outputDataFailure"] = None
    return value


def normal_failure_diagnostics(phase, selection, original, *, engineering=False):
    """Whole-original bounded text to fixed observations, never raw error/reason text."""
    value = failure_base(phase, selection, original, engineering=engineering)
    domains = {domain.encode("ascii"): domain for domain in (
        "NSCocoaErrorDomain", "NSPOSIXErrorDomain", "NSOSStatusErrorDomain", "NSMachErrorDomain",
        "XCTestErrorDomain", "XCTRunnerErrorDomain", "com.apple.dt.xctest.error",
        "IDETestOperationsObserverErrorDomain", "IDEFoundationErrorDomain", "RBSRequestErrorDomain",
        "RBSServiceErrorDomain", "FBSOpenApplicationServiceErrorDomain", "FBSOpenApplicationErrorDomain",
        "IXUserPresentableErrorDomain")}
    codes = (rb"(?:\A|(?<=[ \t\r\n({\x5b]))Error[ \t]{1,8}Domain=(" + b"|".join(re.escape(x) for x in domains)
             + rb")[ \t]{1,8}Code=(-?(?:0|[1-9][0-9]{0,9}))(?=\Z|[ \t\r\n,;\"')}\x5d])")
    methods = (("testEngineeringMainCatalogueAndQuit",) if engineering else
               ("testPositiveAndroidOutputCustodyData",) if selection == OUTPUT_DATA_RESULT else
               (IOS_UNSIGNED_METHOD,) if selection == IOS_UNSIGNED_RESULT else
               NORMAL_SELECTIONS[selection][0]) if selection is not None else ()
    method_pattern = b"|".join(re.escape(m.encode("ascii")) for m in methods)
    case = rb"-\[MRKNormalAppUITests\.NormalAppUITests (?:" + method_pattern + rb")\]"
    locations = (rb"(?:\A|(?<=[/ \t\r\n]))NormalAppUITests\.swift:([1-9][0-9]{0,4})"
                 rb"(?::([1-9][0-9]{0,3}))?:[ \t]{1,8}error:[ \t]{1,8}"
                 rb"-\[MRKNormalAppUITests\.NormalAppUITests (" + method_pattern + rb")\][ \t]{0,8}:")
    markers = {"testExecuteFailed": rb"(?m)^\*\* TEST EXECUTE FAILED \*\*\r?$",
               "testingFailed": rb"(?m)^Testing failed:", "xcodebuildError": rb"(?m)^xcodebuild: error:"}
    compiler_eligible = "compilerDiagnostics" in value
    # These are public SOURCE locations, not arbitrary paths or error prose.
    # No quoted compiler token is published; unknown messages retain their site.
    compiler_site = (rb"(?:(?:/Users/runner/work/mobile-release-kit/mobile-release-kit/)?"
        rb"desktop/native/macos-normal-ui/MRKNormalAppUITests/)?NormalAppUITests\.swift:"
        rb"([1-9][0-9]{0,4}):([1-9][0-9]{0,3}):[ \t]{1,8}(error|note):[ \t]{1,8}([^\r\n\x00]+)")
    compiler_reasons = (
        ("type-mismatch", (b"cannot convert", b"cannot assign value of type", b"cannot be converted")),
        ("missing-member", (b"has no member", b"has no dynamic member")),
        ("missing-name", (b"cannot find", b"use of unresolved identifier")),
        ("inaccessible", (b"is inaccessible due to", b"cannot access")),
        ("missing-argument", (b"missing argument", b"requires an argument")),
        ("extra-argument", (b"extra argument", b"argument passed to call that takes no arguments")),
        ("inference", (b"could not be inferred", b"requires that", b"generic parameter")),
        ("ambiguous-overload", (b"ambiguous", b"no exact matches", b"no matching")),
        ("initialization", (b"before being initialized", b"before all stored properties are initialized",
                            b"used within its own initial value", b"return from initializer without initializing")),
        ("throwing", (b"can throw", b"can throw but is not marked", b"try is not allowed", b"call to throwing")),
        ("actor-isolation", (b"actor-isolated", b"main actor", b"nonisolated", b"async", b"await")),
        ("sendability", (b"sendable", b"sending risks causing data races")),
        ("syntax", (b"expected expression", b"expected declaration", b"expected pattern", b"expected member",
                    b"expected identifier", b"expected '", b"consecutive statements", b"unterminated", b"extraneous")),
        ("redeclaration", (b"invalid redeclaration", b"already declared", b"already defined")),
    ) if compiler_eligible else ()
    if compiler_eligible:
        markers["buildFailed"] = rb"(?m)^\*\* BUILD FAILED \*\*\r?$"
        table = value["destinationTable"]
        table["state"] = "absent"  # No exact header observed, not an eligible-destination count.
        destination_header = (rb'[ \t]{0,32}(Available|Ineligible) destinations for the '
                              rb'"MRKNormalAppUI" scheme:[ \t]{0,32}')
        destination_row = rb"[ \t]{0,32}\{([\x20-\x7e]{1,4094})\}[ \t]{0,32}"
        atom = rb"[\x21-\x2b\x2d-\x7a\x7c\x7e]"  # Neither comma nor braces.
        destination_field = (rb" {0,8}([A-Za-z]{1,8}) {0,8}: {0,8}(" + atom
            + rb"(?:[\x20-\x2b\x2d-\x7a\x7c\x7e]{0,1022}" + atom + rb")?) {0,8}")
    if methods:
        markers.update(selectedCaseStarted=rb"(?m)^Test Case '" + case + rb"' started\.\r?$",
            selectedCaseFailed=rb"(?m)^Test Case '" + case + rb"' failed(?: \([0-9]{1,6}(?:\.[0-9]{1,9})? seconds\))?\.\r?$")
    query = (rb"MRK_MACOS_NORMAL_(RENDERER|DASHBOARD)_QUERY=observation="
             rb"(initial|identifier|title|label|value|placeholderValue|containingSameStaticText)"
             rb";matches=([0-5]);exceedsFour=([01]);nonAtomic=1")

    # Ordinary basic-case grammar stays separate from engineering diagnostics.
    # The packaged-entry route has separate admission and is not added here.
    require_invalid = False
    if phase == "test" and selection == "test.xcresult" and methods == ("testLaunchCancelAndQuit",):
        prefix = b"MRK_MACOS_PACKAGED_REQUIRE_FAILURE"
        attempted = original.stdout.count(prefix)
        if attempted:
            pattern = (rb"(?m)^MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line=([1-9][0-9]{0,4});"
                       rb"check=(condition|singleton|actionable)\r?\n")
            matches = list(re.finditer(pattern, original.stdout))
            # Do not salvage a valid marker next to a malformed/duplicate one,
            # or promote an incomplete record/substring to the first failure.
            if attempted == 1 and len(matches) == 1 and int(matches[0].group(1)) <= 65535:
                value["requireObservations"].append({"source": "NormalAppUITests.swift",
                    "line": int(matches[0].group(1)), "check": matches[0].group(2).decode("ascii")})
            else:
                require_invalid = True

    # Only the existing basic-normal case can pair this supplementary observation.
    dashboard_eligible = (phase == "test" and selection == "test.xcresult"
                          and methods == ("testLaunchCancelAndQuit",))
    dashboard_namespace = b"MRK_MACOS_PACKAGED_DASHBOARD_FAILURE"
    dashboard_pattern = (re.escape(dashboard_namespace) + rb"=v1;line=([1-9][0-9]{0,4});ordinal=([1-4])"
                         rb";waiter=(timed-out|incorrect-order|inverted-fulfillment|interrupted|unknown)"
                         rb";enabled=([01]);hittable=([01]);reason=(loading|not-loaded|bridge-unavailable|"
                         rb"selection-unavailable|selection-in-progress|shutting-down|owner-offline-preflight|"
                         rb"owner-android-build|owner-ios-archive|owner-project-recovery|owner-github-preflight|"
                         rb"owner-github-release|owner-project-path|owner-saved-version-edit|owner-metadata-images|"
                         rb"other-or-unobserved|ambiguous)"
                         rb";sample=pre-wait;nonAtomic=1")
    dashboard_candidates, dashboard_candidate = 0, None
    engineering_require = engineering and phase == "test"
    engineering_namespace = b"MRK_MACOS_ENGINEERING_REQUIRE_FAILURE"
    engineering_pattern = (re.escape(engineering_namespace) + rb"=v1;line=([1-9][0-9]{0,4});"
                           rb"check=(condition|singleton|actionable)")
    engineering_candidates, engineering_candidate = 0, None
    first_namespace = b"MRK_MACOS_ENGINEERING_FIRST_FAILURE"
    first_phases = (b"admission", b"launch", b"catalogue", b"guideSelection", b"artifactStatus", b"artifactSample",
                    b"artifactValue", b"quitCancel", b"postCancel", b"quitConfirm", b"termination", b"terminal")
    first_pattern = (re.escape(first_namespace) + rb"=v1;line=([1-9][0-9]{0,4});phase=("
                     + b"|".join(first_phases) + rb")")
    first_candidates, first_candidate, first_invalid = 0, None, False
    guide_namespace = b"MRK_MACOS_ENGINEERING_GUIDE_QUERY"
    guide_pattern = (re.escape(guide_namespace) + rb"=v1;property=(label|title);type=(any|button|checkBox)"
                     rb";matches=([0-5]);exceedsFour=([01]);nonAtomic=1")
    guide_rows, guide_seen, guide_invalid = [], set(), False
    # Fixed seven actual availability codes plus waiting/error, in SOURCE order.
    # Numeric counts are observations only; 5 denotes more than four matches.
    artifact_states = ("available", "runtime-unqualified", "busy", "shutdown", "cleanup-unknown",
                       "document-lost", "unsupported-platform", "waiting", "error")
    artifact_namespace = b"MRK_MACOS_ENGINEERING_ARTIFACT_QUERY"
    artifact_pattern = (re.escape(artifact_namespace) + rb"=v1;property=(label|title|value);type=staticText"
                        rb";counts=([0-5](?:,[0-5]){8});sample=pre-wait;nonAtomic=1")
    artifact_rows, artifact_seen, artifact_invalid = [], set(), False

    # This supplement belongs only to the fixed DATA method. Never promote raw
    # reason text, dynamic helper messages, or another test's output to a code.
    output_eligible = "outputDataFailure" in value
    output_namespace = b"MRK_MACOS_ANDROID_OUTPUT_DATA_FAILURE"
    output_method = b"-[MRKNormalAppUITests.NormalAppUITests testPositiveAndroidOutputCustodyData"
    output_scenarios = {name.encode("ascii"): name for name in (
        'valid', 'late-close', 'extra-operation', 'work', 'journal', 'project-cache', 'extra-artifact', 'symlink', 'hardlink', 'depth', 'mode', 'input', 'wrong-result', 'identity', 'repeated-start', 'ios-valid', 'ios-work', 'ios-extra-operation', 'ios-foreign-output', 'ios-symlink', 'ios-replacement', 'ios-partial-open', 'ios-late-close', 'ios-input')}
    output_pattern = (re.escape(output_namespace) + rb"=v1;scenario=(" + b"|".join(output_scenarios)
                      + rb");sample=after-cleanup-attempt;originalFailurePreserved=1")
    output_condition = (rb'(?<![A-Za-z0-9_])condition\(("|\\")'
                        rb'([\x20-\x21\x23-\x5b\x5d-\x7e]{1,128})\1\)')
    output_codes = {
        b'fixture: Android AAB byte bound': 'r001',
        b'fixture: Android AAB exact EOF': 'r002',
        b'fixture: Android AAB original read': 'r003',
        b'fixture: Android AAB read bound': 'r004',
        b'fixture: Android DATA adopted root is not the original': 'r005',
        b'fixture: Android DATA census accounting': 'r006',
        b'fixture: Android DATA cleanup original differs': 'r007',
        b'fixture: Android DATA cleanup root close': 'r008',
        b'fixture: Android DATA cleanup root replaced': 'r009',
        b'fixture: Android DATA cleanup row absent': 'r010',
        b'fixture: Android DATA closed deadline refusal': 'r011',
        b'fixture: Android DATA created root facts absent': 'r012',
        b'fixture: Android DATA exact entry limit': 'r013',
        b'fixture: Android DATA fixed original removal': 'r014',
        b'fixture: Android DATA hardlink setup': 'r015',
        b'fixture: Android DATA input parent missing': 'r016',
        b'fixture: Android DATA late close did not clear state and refuse': 'r017',
        b'fixture: Android DATA later close refusal': 'r018',
        b'fixture: Android DATA mode mutation': 'r019',
        b'fixture: Android DATA original parent replaced': 'r020',
        b'fixture: Android DATA original parent row absent': 'r021',
        b'fixture: Android DATA primary closure failure was masked or state retained': 'r022',
        b'fixture: Android DATA private root retirement': 'r023',
        b'fixture: Android DATA production close deleted output': 'r024',
        b'fixture: Android DATA scenario unmapped': 'r025',
        b'fixture: Android DATA symlink setup': 'r026',
        b'fixture: Android DATA temporary close': 'r027',
        b'fixture: Android DATA unopened cleanup root differs': 'r028',
        b'fixture: Android DATA unopened private root retirement': 'r029',
        b'fixture: Android XML original consuming close failed': 'r030',
        b'fixture: Android XML original content differs': 'r031',
        b'fixture: Android XML resource consuming close failed': 'r032',
        b'fixture: Android XML resource content or original changed': 'r033',
        b'fixture: Android XML resource open failed': 'r034',
        b'fixture: Android XML resource parent changed': 'r035',
        b'fixture: Android XML resource parent open failed': 'r036',
        b'fixture: Android XML resource parent shape or binding': 'r037',
        b'fixture: Android XML resource read failed': 'r038',
        b'fixture: Android XML resource read limit': 'r039',
        b'fixture: Android XML resource shape, binding or exact length': 'r040',
        b'fixture: Android captured AAB mode': 'r041',
        b'fixture: Android census enumeration conversion': 'r042',
        b'fixture: Android census enumeration failed': 'r043',
        b'fixture: Android census enumeration open': 'r044',
        b'fixture: Android census limit selection': 'r045',
        b'fixture: Android current build identity shape': 'r046',
        b'fixture: Android current terminal artifact differs': 'r047',
        b'fixture: Android earlier consuming close failed': 'r048',
        b'fixture: Android final output observation was not joined before close': 'r049',
        b'fixture: Android immutable input changed': 'r050',
        b'fixture: Android input consuming close failed': 'r051',
        b'fixture: Android input directory roster': 'r052',
        b'fixture: Android input parent absent': 'r053',
        b'fixture: Android input roster consuming close failed': 'r054',
        b'fixture: Android module output byte bound': 'r055',
        b'fixture: Android operation output roster': 'r056',
        b'fixture: Android original Start identity or state differs': 'r057',
        b'fixture: Android output DATA case deadline': 'r058',
        b'fixture: Android output DATA cleanup original': 'r059',
        b'fixture: Android output DATA cleanup parent': 'r060',
        b'fixture: Android output DATA create leaf': 'r061',
        b'fixture: Android output DATA creation consuming close': 'r062',
        b'fixture: Android output DATA exact refusal missing': 'r063',
        b'fixture: Android output DATA leaf write': 'r064',
        b'fixture: Android output DATA mkdir': 'r065',
        b'fixture: Android output DATA private root creation': 'r067',
        b'fixture: Android output DATA temporary consuming close': 'r068',
        b'fixture: Android output DATA temporary original': 'r069',
        b'fixture: Android output canonical duplicate': 'r070',
        b'fixture: Android output census name or entry bound': 'r071',
        b'fixture: Android output closure is not terminal': 'r072',
        b'fixture: Android output consuming close failed': 'r073',
        b'fixture: Android output depth bound': 'r074',
        b'fixture: Android output enumeration consuming close failed': 'r075',
        b'fixture: Android output existed before review': 'r076',
        b'fixture: Android output name encoding': 'r077',
        b'fixture: Android output name length': 'r078',
        b'fixture: Android output named binding unavailable': 'r079',
        b'fixture: Android output named directory changed': 'r080',
        b'fixture: Android output observation repeated or mixed with Save': 'r081',
        b'fixture: Android output original POST': 'r082',
        b'fixture: Android output original alias': 'r083',
        b'fixture: Android output original directory changed': 'r084',
        b'fixture: Android output original open': 'r085',
        b'fixture: Android output parent absent': 'r086',
        b'fixture: Android output regular leaf shape': 'r087',
        b'fixture: Android output root absent or type': 'r088',
        b'fixture: Android output roster changed': 'r089',
        b'fixture: Android output total byte bound': 'r090',
        b'fixture: Android output type owner mode or binding': 'r091',
        b'fixture: Android parsed terminal artifact shape': 'r092',
        b'fixture: Android positive input prerequisites absent': 'r093',
        b'fixture: Android private output directory mode': 'r094',
        b'fixture: Android private root output roster': 'r095',
        b'fixture: Android project AAB candidate roster': 'r096',
        b'fixture: Android report byte bound': 'r097',
        b'fixture: Android report output roster': 'r098',
        b'fixture: Android report parent roster': 'r099',
        b'fixture: Android required AAB observations absent': 'r100',
        b'fixture: Android retained artifact roster': 'r101',
        b'fixture: Android retained output changed': 'r102',
        b'fixture: Android root build output roster': 'r103',
        b'fixture: Android root census bound': 'r104',
        b'fixture: Android running original identity differs': 'r105',
        b'fixture: Android terminal original identity differs': 'r106',
        b'fixture: Android unexpected input-adjacent output': 'r107',
        b'fixture: Android unrecognized output directory': 'r108',
        b'fixture: Android unrecognized output leaf': 'r109',
        b'fixture: Android work or journal remains': 'r110',
        b'fixture: admitted Android XML pin differs': 'r111',
        b'fixture: an earlier consuming close failed': 'r112',
        b'fixture: directory binding changed': 'r113',
        b'fixture: directory entry changed': 'r114',
        b'fixture: directory open failed': 'r115',
        b'fixture: directory original changed': 'r116',
        b'fixture: fixed Android XML original was not admitted': 'r117',
        b'fixture: fixed Android XML resource absent or misplaced': 'r118',
        b'fixture: fixed leaf changed during observation': 'r119',
        b'fixture: fixed leaf open failed': 'r120',
        b'fixture: fixed leaf read failed': 'r121',
        b'fixture: fixed leaf read limit': 'r122',
        b'fixture: leaf shape/mode/limit': 'r123',
        b'fixture: missing fixed parent': 'r124',
        b'fixture: not an original directory': 'r125',
        b'fixture: original descriptor stat failed': 'r126',
        b'fixture: owned roster changed during enumeration': 'r127',
        b'fixture: owned roster conversion failed': 'r128',
        b'fixture: owned roster limit/duplicate': 'r129',
        b'fixture: owned roster open failed': 'r130',
        b'fixture: owned roster read failed': 'r131',
        b'fixture: Android output DATA private original root mode differs': 'r132',
        b'fixture: Android output DATA private original root uid differs': 'r133',
        b'fixture: Android output DATA private original root gid differs': 'r134',
        b'fixture: Android output DATA private original root flags differ': 'r135',
        b'fixture: Android output DATA private original root kind differs': 'r136',
        b'fixture: Android output DATA private original root descriptor differs': 'r137',
        b'fixture: Android output DATA private original root entry differs': 'r138',
        b'fixture: new private root initialization precondition': 'r139',
        b'fixture: new private root group initialization failed': 'r140',
        b'fixture: new private root initialization transition differs': 'r141',
        b'fixture: iOS original identity shape': 'r142',
        b'fixture: iOS fixed profile or repeated review': 'r143',
        b'fixture: iOS original Start identity or state': 'r144',
        b'fixture: iOS terminal original identity or directory count': 'r145',
        b'fixture: iOS settled top-level output roster': 'r146',
        b'fixture: iOS output enumeration consuming close': 'r147',
        b'fixture: iOS terminal original identity or state': 'r148',
        b'fixture: iOS input project absent': 'r149',
        b'fixture: iOS output original mode owner or filesystem': 'r150',
        b'fixture: iOS output closure is not terminal': 'r151',
        b'fixture: iOS final output observation was not joined before close': 'r152',
        b'fixture: iOS DATA symlink setup': 'r153',
        b'fixture: iOS DATA input mutation': 'r154',
        b'fixture: iOS DATA fixed original descriptor census': 'r155',
        b'fixture: iOS DATA same-parent replacement setup': 'r156',
        b'fixture: iOS DATA closed deadline refusal': 'r157',
        b'fixture: iOS DATA consuming close and late refusal': 'r158',
        b'fixture: iOS DATA production observation deleted archive': 'r159',
        b'fixture: iOS DATA scenario unmapped': 'r160',
        b'fixture: iOS DATA partial opens not retained': 'r161',
        b'fixture: unexpected owned output under project': 'r162',
    } if output_eligible else {}
    output_markers, output_failures = 0, 0
    output_scenario = output_reason = output_site = None
    output_invalid = False

    def retain(key, finding, maximum, distinct=True):
        if not distinct or finding not in value[key]:
            if len(value[key]) < maximum:
                value[key].append(finding)
            else:
                value["findingsTruncated"] = True

    for stream, body in (("stdout", original.stdout), ("stderr", original.stderr)):
        destination_section = None  # A header never lends authority across streams.
        for key, pattern in markers.items():
            value["markers"][key] = value["markers"][key] or re.search(pattern, body) is not None
        for match in re.finditer(codes, body):
            token = match.group(2)
            code = int(token)
            if token != b"-0" and -2147483648 <= code <= 2147483647:
                retain("errorCodes", {"stream": stream, "domain": domains[match.group(1)], "code": code}, 8)
        if methods:
            for match in re.finditer(locations, body):
                line, column = int(match.group(1)), int(match.group(2)) if match.group(2) is not None else None
                if line <= 65535 and (column is None or column <= 4096):
                    retain("sourceFailures", {"stream": stream, "source": "NormalAppUITests.swift",
                        "method": match.group(3).decode("ascii"), "line": line, "column": column}, 4)
        offset = 0
        while offset < len(body):
            end = body.find(b"\n", offset)
            complete = end != -1
            if not complete:
                end = len(body)
            record, offset = body[offset:end], end + 1
            if complete and record.endswith(b"\r"):
                record = record[:-1]
            if compiler_eligible:
                bounded = complete and len(record) <= 4096
                header = re.fullmatch(destination_header, record) if bounded else None
                if header is not None:
                    destination_section = "available" if header.group(1) == b"Available" else "ineligible"
                    table["state"] = "observed"
                elif destination_section is not None and record.lstrip(b" \t").startswith(b"{"):
                    if not bounded:
                        table["rowsTruncated"] = value["findingsTruncated"] = True
                    else:
                        row_match = re.fullmatch(destination_row, record)
                        fields = row_match.group(1).split(b",", 5) if row_match is not None else []
                        parts, malformed = {}, not 1 <= len(fields) <= 5
                        for field in fields if not malformed else ():
                            item = re.fullmatch(destination_field, field)
                            if item is None or item.group(1) in parts:
                                malformed = True
                                break
                            parts[item.group(1)] = item.group(2)
                        if malformed or not {b"platform", b"name"} <= parts.keys():
                            table["malformedRowObserved"] = True
                        elif (not parts.keys() <= {b"platform", b"arch", b"id", b"name", b"error"}
                              or parts[b"platform"] != b"macOS"
                              or parts.get(b"arch") not in (None, b"arm64", b"x86_64")):
                            table["unknownRowObserved"] = True
                        elif len(table["rows"]) == 8:
                            table["rowsTruncated"] = value["findingsTruncated"] = True
                        else:
                            # Opaque id/name/error fields never escape as text or per-value hashes.
                            table["rows"].append({"stream": stream, "section": destination_section,
                                "platform": "macos", "architecture": parts[b"arch"].decode("ascii")
                                if b"arch" in parts else None, "errorPresent": b"error" in parts})
                elif record.strip(b" \t"):
                    destination_section = None
                if complete and len(record) <= 4096:
                    # Fixed diagnostic categories only: do not publish scheme names,
                    # destination identifiers, variable message tails, or raw text.
                    if record == b"xcodebuild: error: Unable to find a destination matching the provided destination specifier:":
                        retain("buildFailureReasons", {"stream": stream, "code": "destination-not-found"}, 4)
                    elif re.fullmatch(rb"xcodebuild: error: Found no destinations for the scheme [\x20-\x7e]{1,256} and action [\x20-\x7e]{1,32}\.", record):
                        retain("buildFailureReasons", {"stream": stream, "code": "no-eligible-destination"}, 4)
                    site = re.fullmatch(compiler_site, record)
                    if site is not None and int(site.group(1)) <= 65535 and int(site.group(2)) <= 4096:
                        message = site.group(4).lower()  # Local only; never returned or logged.
                        finding = {"stream": stream, "source": "NormalAppUITests.swift",
                            "line": int(site.group(1)), "column": int(site.group(2)),
                            "severity": site.group(3).decode("ascii"),
                            "reasonCodes": [code for code, tokens in compiler_reasons
                                            if any(token in message for token in tokens)][:3]}
                        rows = value["compilerDiagnostics"]
                        if finding not in rows:
                            rows.append(finding)
                            rows.sort(key=lambda row: row["severity"] != "error")  # Errors precede optional notes.
                            if len(rows) > 4:
                                rows.pop()
                                value["findingsTruncated"] = True
                elif b"NormalAppUITests.swift:" in record:
                    value["findingsTruncated"] = True  # Never classify partial or oversized records.
            if output_eligible:
                attempted_marker = (output_namespace in record or (record and output_namespace.startswith(record))
                    or (not complete and any(record.endswith(output_namespace[:size])
                                             for size in range(1, len(output_namespace)))))
                if attempted_marker:
                    output_markers = min(2, output_markers + 1)
                    match = re.fullmatch(output_pattern, record) if complete and stream == "stdout" else None
                    if output_markers != 1 or match is None:
                        output_invalid = True
                    else:
                        output_scenario = output_scenarios[match.group(1)]
                attempted_site = (b"NormalAppUITests.swift:" in record
                                  and (output_method in record or not complete))
                if attempted_site:
                    output_failures = min(2, output_failures + 1)
                    site = re.search(locations, record) if complete and stream == "stdout" else None
                    if (output_failures != 1 or site is None or record.count(output_method) != 1
                            or record.count(b"NormalAppUITests.swift:") != 1 or int(site.group(1)) > 65535
                            or (site.group(2) is not None and int(site.group(2)) > 4096)):
                        output_invalid = True
                    else:
                        output_site = (int(site.group(1)), int(site.group(2)) if site.group(2) is not None else None)
                        payloads = record.count(b"condition(")
                        if payloads:
                            payload = re.search(output_condition, record[site.end():]) if payloads == 1 else None
                            if payload is None:
                                output_invalid = True
                            else:
                                output_reason = output_codes.get(payload.group(2))
                # Do not continue: existing finite diagnostics retain their exact
                # findings even when a mixed/partial DATA supplement is refused.
            if engineering and (guide_namespace in record or (record and guide_namespace.startswith(record))
                    or (not complete and any(record.endswith(guide_namespace[:size])
                                             for size in range(1, len(guide_namespace))))):
                match = re.fullmatch(guide_pattern, record) if engineering_require and complete and stream == "stdout" else None
                if match is None:
                    guide_invalid = True
                else:
                    key = (match.group(1), match.group(2))
                    count, exceeds = int(match.group(3)), match.group(4) == b"1"
                    if key in guide_seen or exceeds != (count == 5):
                        guide_invalid = True
                    else:
                        guide_seen.add(key)  # Exactly two properties by three types: at most six rows.
                        guide_rows.append({"stream": "stdout", "kind": "guide", "property": key[0].decode("ascii"),
                            "elementType": key[1].decode("ascii"), "matches": count,
                            "exceedsFour": exceeds, "nonAtomic": True})
                # Still examine other fixed namespaces on this record; a malformed
                # mixed/partial line cannot hide a duplicate first-failure marker.
            if engineering and (artifact_namespace in record or (record and artifact_namespace.startswith(record))
                    or (not complete and any(record.endswith(artifact_namespace[:size])
                                             for size in range(1, len(artifact_namespace))))):
                match = re.fullmatch(artifact_pattern, record) if engineering_require and complete and stream == "stdout" else None
                if match is None or match.group(1) in artifact_seen:
                    artifact_invalid = True
                else:
                    artifact_seen.add(match.group(1))  # Exactly three properties; never deduplicate evidence.
                    artifact_rows.append({"stream": "stdout", "kind": "artifactAvailability",
                        "property": match.group(1).decode("ascii"), "elementType": "staticText",
                        "counts": dict(zip(artifact_states, map(int, match.group(2).split(b",")))),
                        "sample": "pre-wait", "nonAtomic": True})
                # Keep checking fixed namespaces so mixed lines cannot hide old failures.
            if engineering and (first_namespace in record or (record and first_namespace.startswith(record))
                    or (not complete and any(record.endswith(first_namespace[:size])
                                             for size in range(1, len(first_namespace))))):
                first_candidates = min(2, first_candidates + 1)
                match = re.fullmatch(first_pattern, record) if engineering_require and complete and stream == "stdout" else None
                if first_candidates != 1 or match is None or int(match.group(1)) > 65535:
                    first_invalid = True
                    first_candidate = None
                else:
                    first_candidate = {"line": int(match.group(1)), "phase": match.group(2).decode("ascii")}
                # Examine other fixed namespaces too; a mixed line cannot hide a duplicate.
            if engineering_require and (engineering_namespace in record
                    or (record and engineering_namespace.startswith(record))
                    or (not complete and any(record.endswith(engineering_namespace[:size])
                                             for size in range(1, len(engineering_namespace))))):
                engineering_candidates = min(2, engineering_candidates + 1)
                match = re.fullmatch(engineering_pattern, record) if complete and stream == "stdout" else None
                engineering_candidate = None
                if engineering_candidates == 1 and match is not None and int(match.group(1)) <= 65535:
                    engineering_candidate = {"source": "NormalAppUITests.swift",
                        "line": int(match.group(1)), "check": match.group(2).decode("ascii")}
                continue
            if dashboard_eligible and (dashboard_namespace in record or (record and dashboard_namespace.startswith(record))
                    or (not complete and any(record.endswith(dashboard_namespace[:size])
                                             for size in range(1, len(dashboard_namespace))))):
                dashboard_candidates = min(2, dashboard_candidates + 1)
                match = re.fullmatch(dashboard_pattern, record) if complete else None
                dashboard_candidate = None
                if dashboard_candidates == 1 and match is not None and int(match.group(1)) <= 65535:
                    dashboard_candidate = {"stream": stream, "line": int(match.group(1)), "ordinal": int(match.group(2)),
                        "waiter": match.group(3).decode("ascii"), "enabled": match.group(4) == b"1",
                        "hittable": match.group(5) == b"1", "reason": match.group(6).decode("ascii"),
                        "sample": "pre-wait", "nonAtomic": True}
                continue
            if not complete:
                break  # Incomplete records may veto dashboard pairing, never become query observations.
            if engineering:
                continue  # Do not import ordinary query observations into this separate fixture.
            match = re.fullmatch(query, record)
            if match is None:
                continue
            kind = "renderer" if match.group(1) == b"RENDERER" else "dashboard"
            observation, count = match.group(2).decode("ascii"), int(match.group(3))
            exceeds = match.group(4) == b"1"
            if (kind == "renderer" and observation != "initial") or (observation == "initial" and count == 1):
                continue
            if exceeds == (count == 5):
                retain("queryObservations", {"stream": stream, "kind": kind, "observation": observation,
                    "matches": count, "exceedsFour": exceeds, "nonAtomic": True}, 4, distinct=False)
    if engineering_require and not guide_invalid:
        value["queryObservations"] = guide_rows  # Partial sets stay partial/nonAtomic, never padded or authoritative.
    if engineering_require and not artifact_invalid:
        value["queryObservations"].extend(artifact_rows)  # Partial sets remain partial, never zero-filled.
    if engineering_require and first_candidates == 1 and not first_invalid:
        value["engineeringFirstFailure"] = first_candidate
    if engineering_require and engineering_candidates:
        if engineering_candidates == 1 and engineering_candidate is not None:
            value["requireObservations"].append(engineering_candidate)
        else:
            require_invalid = True
    if (dashboard_eligible and not require_invalid and dashboard_candidates == 1
            and dashboard_candidate is not None and len(value["requireObservations"]) == 1
            and original.stderr.count(b"MRK_MACOS_PACKAGED_REQUIRE_FAILURE") == 0):
        site = value["requireObservations"][0]
        if (site["check"] == "condition" and site["line"] == dashboard_candidate["line"]
                and dashboard_candidate["stream"] == "stdout"):
            value["dashboardReadiness"] = dashboard_candidate
    if output_eligible and not output_invalid and (output_scenario is not None or output_reason is not None):
        value["outputDataFailure"] = {"scenario": output_scenario, "reasonCode": output_reason,
            "source": "NormalAppUITests.swift", "method": "testPositiveAndroidOutputCustodyData",
            "line": output_site[0] if output_site is not None else None,
            "column": output_site[1] if output_site is not None else None,
            "sample": "after-cleanup-attempt" if output_scenario is not None else None}
    if compiler_eligible:
        # New optional observations cannot displace old findings or their cap.
        # Reserve two bytes for the final status string below.
        while table["rows"] and len(encoded(value)) + 1 > 4094:
            table["rows"].pop()
            table["rowsTruncated"] = value["findingsTruncated"] = True
        if len(encoded(value)) + 1 > 4094:
            del value["destinationTable"]  # Even optional metadata cannot displace old facts.
            value["findingsTruncated"] = True
        while value["buildFailureReasons"] and len(encoded(value)) + 1 > 4094:
            value["buildFailureReasons"].pop()
            value["findingsTruncated"] = True
        while value["compilerDiagnostics"] and len(encoded(value)) + 1 > 4094:
            value["compilerDiagnostics"].pop()
            value["findingsTruncated"] = True
    value["status"] = ("unavailable" if require_invalid or guide_invalid or artifact_invalid or first_invalid or output_invalid else "classified" if any(value[key]
        for key in ("errorCodes", "sourceFailures", "queryObservations", "requireObservations"))
        or value.get("engineeringFirstFailure") is not None or value.get("outputDataFailure") is not None or value.get("compilerDiagnostics") or value.get("buildFailureReasons") else "unclassified")
    need(len(encoded(value)) + 1 <= 4096, "normal-diagnostic-output-bound")
    return value


def publish_failure_diagnostics(request, original, *, query=False, role=None):
    phase = "query" if query else request["phase"]
    selection = None if phase in ("build", "query") else request["result"].name
    # Validate before formatting: caller must already hold a genuine returned nonzero original.
    unavailable = failure_base(phase, selection, original)
    if request.get("outputData") is True:
        need(role in ("one-admitted-ui-test", "normal-ui-summary", "normal-ui-test-tree"), "output-data-failed-role")
        unavailable["originalCommandRole"] = role
    try:
        value = normal_failure_diagnostics(phase, selection, original)
        if request.get("outputData") is True:
            value["originalCommandRole"] = role
        body = encoded(value) + b"\n"
        need(len(body) <= 4096, "normal-diagnostic-output-bound")
    except Exception:
        body = encoded(unavailable) + b"\n"
    name = ("toolchain" if query else "build" if phase == "build" else
            SUMMARY_STEMS[selection] if phase == "summary" else request["result"].stem)
    try:
        exclusive_output(request["derived"].parent / (name + ".failure-diagnostics.json"), body, 4096)
    except Exception:
        # A formatter/output failure cannot turn the original native nonzero into success.
        try:
            sys.stderr.write("normal-failure-diagnostic-publication-failed\n")
        except Exception:
            pass


def load_normal_owner(root):
    # Real dataclasses with postponed annotations need their original defining
    # module registered before execution (the documented importlib lifecycle).
    need(LOADER_MODULE not in sys.modules, "normal-owner-loader-collision")
    loader_fd = os.open(root / LOADER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    loader = owner = failure = None
    registered = False
    try:
        _, loader_identity, loader_digest = original_body(loader_fd, 1024 * 1024)
        need(loader_digest == LOADER_SHA, "normal-owner-loader-pin")

        def unchanged():
            need(full9(os.stat(root / LOADER, follow_symlinks=False)) == loader_identity
                 and original_body(loader_fd, 1024 * 1024)[1:] == (loader_identity, loader_digest),
                 "normal-owner-loader-changed")

        unchanged()
        spec = importlib.util.spec_from_file_location(LOADER_MODULE, root / LOADER)
        need(spec is not None and spec.loader is not None, "normal-owner-loader")
        loader = importlib.util.module_from_spec(spec)
        need(LOADER_MODULE not in sys.modules, "normal-owner-loader-collision")
        sys.modules[LOADER_MODULE] = loader
        registered = True
        spec.loader.exec_module(loader)
        need(sys.modules.get(LOADER_MODULE) is loader, "normal-owner-loader-registry-changed")
        unchanged()  # Do not enter core loading after a changed helper/registry.
        owner = loader.load_owner(root)
        need(sys.modules.get(LOADER_MODULE) is loader, "normal-owner-loader-registry-changed")
        unchanged()
    except BaseException as error:
        failure = error
    finally:
        try:
            os.close(loader_fd)  # One original attempt, including failure paths.
        except BaseException as error:
            if failure is None:
                failure = error
    if failure is not None:
        if registered and sys.modules.get(LOADER_MODULE) is loader:
            del sys.modules[LOADER_MODULE]  # Never delete a replacement's entry.
        raise failure
    return owner


ADMISSION_STAGES = ("request", "context", "loader", "phase", "execute", "diagnostic", "publication", "finalize")
ADMISSION_EXCEPTION_TYPES = (Refused, AttributeError, TypeError, ValueError, ImportError,
    ModuleNotFoundError, OSError, FileNotFoundError, PermissionError, RuntimeError,
    KeyError, AssertionError, KeyboardInterrupt, SystemExit)
ADMISSION_EXCEPTION_LABELS = tuple(kind.__name__ for kind in ADMISSION_EXCEPTION_TYPES) + (
    "ProcessError", "ProcessInterrupted", "other")
ADMISSION_SOURCE_FILES = ("desktop/tools/macos_normal_ui_runner.py", LOADER,
                          "src/mobile_release/owned_process.py")
ADMISSION_COMMAND_ROLES = ("normal-ui-source-roster", "normal-ui-build", "normal-ui-summary",
    "saved-version-source-roster", "saved-version-core-interrupt",
    "verify-generated-runner", "generated-runner-entitlements", "one-admitted-ui-test", "normal-ui-test-tree",
    *("normal-toolchain-" + key for key, _, _ in TOOLCHAIN_QUERIES))


def normal_admission_failure(stage, error, owner, records):
    """Closed exception facts only: no messages, locals, paths or native output."""
    label = next((kind.__name__ for kind in ADMISSION_EXCEPTION_TYPES if type(error) is kind), "other")
    owner_failure = dict(dispatched=None, contained=None, cleanupComplete=None)
    if owner is not None and isinstance(error, (owner.ProcessError, owner.ProcessInterrupted)):
        label = "ProcessInterrupted" if isinstance(error, owner.ProcessInterrupted) else "ProcessError"
        owner_failure = {name: value if type(value := getattr(error, attribute, None)) is bool else None
            for name, attribute in (("dispatched", "dispatched"), ("contained", "contained"),
                                    ("cleanupComplete", "cleanup_complete"))}
    root = Path(__file__).absolute().parents[2]
    allowed = {str(root / name): Path(name).name for name in ADMISSION_SOURCE_FILES}
    frames = []
    current = error.__traceback__
    for _ in range(64):
        if current is None or len(frames) == 4:
            break
        filename, line = current.tb_frame.f_code.co_filename, current.tb_lineno
        if filename in allowed and type(line) is int and 1 <= line <= 1_000_000:
            frames.append({"source": allowed[filename], "line": line})
        current = current.tb_next
    result = {"schemaVersion": 1, "scope": "generated-ui-runner-refused", "productReady": False,
        "error": "runner-admission-or-owner-error", "stage": stage, "exceptionClass": label,
        "sourceFrames": frames, "commands": records, "ownerFailure": owner_failure, "unknownStateRetained": True}
    if stage == "execute" and type(error) is Refused and error.args == ("output-data-result-post",):
        try:
            result["resultPost"] = admit_output_data_result_post(
                getattr(error, "_output_data_result_post", None), records)
        except BaseException:
            pass  # No invalid/absent optional metadata changes the primary error.
    return result


def classify_normal_admission_failure(body):
    """A whole exception-only JSON record, never a search of private native logs."""
    unavailable = {"schemaVersion": 1, "scope": "normal-macos-ui-admission-diagnostic-only",
        "status": "unavailable", "nativeSuccessInferred": False, "productReady": False,
        "unknownStateRetained": True}
    try:
        value = document(body)
        fields = {"schemaVersion", "scope", "productReady", "error", "stage", "exceptionClass",
                  "sourceFrames", "commands", "ownerFailure", "unknownStateRetained"}
        need(set(value) in (fields, fields | {"resultPost"}), "admission-fields")
        need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
             and value["scope"] == "generated-ui-runner-refused" and value["productReady"] is False
             and value["error"] == "runner-admission-or-owner-error" and value["unknownStateRetained"] is True
             and value["stage"] in ADMISSION_STAGES and value["exceptionClass"] in ADMISSION_EXCEPTION_LABELS,
             "admission-values")
        frames = value["sourceFrames"]
        need(type(frames) is list and len(frames) <= 4, "admission-frames")
        for frame in frames:
            need(type(frame) is dict and set(frame) == {"source", "line"}
                 and frame["source"] in tuple(Path(name).name for name in ADMISSION_SOURCE_FILES)
                 and type(frame["line"]) is int and 1 <= frame["line"] <= 1_000_000, "admission-frame")
        owner = value["ownerFailure"]
        need(type(owner) is dict and set(owner) == {"dispatched", "contained", "cleanupComplete"}
             and all(item is None or type(item) is bool for item in owner.values()), "admission-owner")
        commands = value["commands"]
        need(type(commands) is list and len(commands) <= 16, "admission-commands")
        projected = []
        for command in commands:
            need(type(command) is dict and set(command) == {"role", "returncode", "timeoutSeconds", "roleCapSeconds",
                 "outputLimitBytes", "argvSha256", "stdoutBytes", "stdoutSha256", "stderrBytes", "stderrSha256"},
                 "admission-command")
            need(command["role"] in ADMISSION_COMMAND_ROLES
                 and all(type(command[key]) is int for key in ("returncode", "timeoutSeconds", "roleCapSeconds",
                         "outputLimitBytes", "stdoutBytes", "stderrBytes"))
                 and 0 <= command["returncode"] <= 255
                 and 1 <= command["timeoutSeconds"] <= command["roleCapSeconds"] <= 720
                 and 1 <= command["outputLimitBytes"] <= 1024 * 1024
                 and 0 <= command["stdoutBytes"] <= command["outputLimitBytes"]
                 and 0 <= command["stderrBytes"] <= command["outputLimitBytes"] - command["stdoutBytes"]
                 and all(type(command[key]) is str and re.fullmatch(r"[0-9a-f]{64}", command[key])
                         for key in ("argvSha256", "stdoutSha256", "stderrSha256")), "admission-command-values")
            projected.append({key: command[key] for key in ("role", "returncode", "stdoutBytes", "stderrBytes")})
        result = dict(unavailable, status="observed-exception-only", stage=value["stage"],
            exceptionClass=value["exceptionClass"], sourceFrames=frames, ownerFailure=owner, commands=projected)
        if "resultPost" in value:
            need(value["stage"] == "execute" and value["exceptionClass"] == "Refused",
                 "output-data-post-exception-context")
            result["resultPost"] = admit_output_data_result_post(value["resultPost"], commands)
        need(len(encoded(result)) + 1 <= 4096, "admission-projection-bound")
        return result
    except Exception:
        return unavailable


def normal_context(request):
    machine, hosted_job = normal_target_data(request["target"])
    source = os.environ.get("TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE", "")
    need(re.fullmatch(r"[0-9a-f]{40}", source)
         and os.environ.get("TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE") == source
         and os.environ.get("TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB") == hosted_job,
         "normal-same-build-only")
    import resource  # Native CLI only; inert helper import stays portable.
    need(sys.platform == "darwin" and platform.machine() == machine and platform.mac_ver()[0].startswith("26.")
         and os.environ.get("DEVELOPER_DIR") == DEVELOPER, "normal-host-developer-file-budget")
    file_limit = normal_file_limit(request["phase"], resource.getrlimit(resource.RLIMIT_FSIZE))
    import pwd
    account = pwd.getpwuid(os.getuid())
    need(os.getuid() > 0 and os.getuid() == os.geteuid() == account.pw_uid
         and os.getgid() == os.getegid() == account.pw_gid and account.pw_name == "runner"
         and account.pw_dir == "/Users/runner" and os.stat("/dev/console").st_uid == os.getuid(), "normal-console-account")
    root = Path(__file__).absolute().parents[2]
    derived = request["derived"]
    need(str(root) == "/Users/runner/work/mobile-release-kit/mobile-release-kit" and Path.cwd() == root
         and derived.parent.parent.parent == Path("/Users/runner/work/_temp")
         and re.fullmatch(r"mrk-macos-installed\.[A-Za-z0-9]{8}", derived.parent.parent.name)
         and os.environ.get("TMPDIR") == str(derived.parent / "tmp") + "/", "normal-fixed-work")
    environment = {key: os.environ[key] for key in ("PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "TZ",
        "DEVELOPER_DIR", "TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB", "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE",
        "TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE")}
    need(all(environment[key] == value for key, value in {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
         "HOME": "/Users/runner", "USER": "runner", "LOGNAME": "runner", "LANG": "en_US.UTF-8",
         "LC_ALL": "en_US.UTF-8", "TZ": "UTC"}.items()), "normal-clean-environment")
    if request.get("androidPositive") is True:
        env = os.environ
        need(request["target"] == ARM_TARGET and sys.version_info[:3] == (3, 14, 7)
             and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
             and env.get("GITHUB_REPOSITORY") == "Apdelrahman1911/mobile-release-kit"
             and env.get("GITHUB_EVENT_NAME") == "push" and env.get("GITHUB_REF") == ANDROID_REF
             and env.get("GITHUB_SHA") == source == env.get("GITHUB_WORKFLOW_SHA")
             and env.get("GITHUB_WORKFLOW_REF") == "Apdelrahman1911/mobile-release-kit/" + ANDROID_WORKFLOW + "@" + ANDROID_REF
             and env.get("GITHUB_WORKSPACE") == str(root) and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
             and env.get("RUNNER_OS") == "macOS" and env.get("RUNNER_ARCH") == "ARM64"
             and all(re.fullmatch(r"[1-9][0-9]{0,19}", env.get(k, "")) for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")),
             "android-signed-fixed-installed-context")
        handoff = str(derived.parent / "android-input-fixture.json")
        # Derived from this admitted fixed work, never a caller-supplied private path.
        environment.update({ANDROID_INPUT_ENV: handoff, ANDROID_RUN_ENV: env["GITHUB_RUN_ID"],
                            ANDROID_ATTEMPT_ENV: env["GITHUB_RUN_ATTEMPT"]})
    return root, source, environment, file_limit


# A separate closed, credential-free main-UI fixture. Ordinary/packaged inputs
# never select it, and its result cannot satisfy an installed qualification.
ENGINEERING_WORKFLOW = ".github/workflows/desktop-macos-engineering-ui.yml"
ENGINEERING_REF = "refs/heads/verify/desktop-macos-engineering-ui"
ENGINEERING_SCOPE = "macos-engineering-ui-compile-v1"
ENGINEERING_COMPILE_EVIDENCE = "desktop-macos-engineering-ui-compile-only-v1"
ENGINEERING_METHOD = CLASS + "testEngineeringMainCatalogueAndQuit"
ENGINEERING_PLIST = "desktop/native/macos-normal-ui/engineering-main-app.plist"
ENGINEERING_APP = "Mobile Release Kit.app"
ENGINEERING_IDENTIFIER = "dev.mobile-release-kit.engineering-ui"
ENGINEERING_EXECUTABLE = "mobile-release-kit-desktop"
ENGINEERING_MAIN_BYTES = 256 * 1024 * 1024
ENGINEERING_MODES = {"--engineering-main-build": "build", "--engineering-main-test": "test",
                     "--engineering-main-summary": "summary"}
ENGINEERING_CHECKS = {
    "acquire": ("rust-version-target", "mac-cargo-version", "locked-platform-metadata", "node-version", "npm-locked-no-scripts"),
    "compile": ("rust-version-target", "mac-cargo-version", "node-version", "typescript-no-emit", "vite-assets", "tauri-debug-compile-only"),
}
ENGINEERING_RUST = {"release": "1.98.1", "commitHash": "48a229ceaefd4985c50990b14116b6d856af0985", "target": ARM_TARGET}
ENGINEERING_MARKER = ("MRK_MACOS_ENGINEERING_MAIN_UI=mainRequest=1;completion=1;body=1;handoff=1;"
    "mainIdentity=1;catalogueGuide=1;projectSelected=0;editCapability=unavailable;originalTerminated=1;"
    "failureCleanup=0;caseDeadlineMet=1;cleanExitStatus=unavailable;allWorkerFinality=unavailable")
ENGINEERING_BINDINGS = ("sourceSha", "sourceTree", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt", "engineeringWork")


def engineering_request(arguments, temporary):
    need(type(arguments) is list and len(arguments) == 3 and all(type(item) is str for item in arguments)
         and arguments[0] in ENGINEERING_MODES and arguments[1] == "--work", "engineering-fixed-command")
    work = Path(arguments[2])
    need(str(work) == arguments[2] and work.parent == Path("/Users/runner/work/_temp")
         and re.fullmatch(r"mrk-macos-engineering-ui\.[A-Za-z0-9]{8}", work.name)
         and temporary == str(work / "normal-ui/tmp") + "/", "engineering-fixed-work")
    mode = ENGINEERING_MODES[arguments[0]]
    return dict(engineering=True, phase=mode, target=ARM_TARGET, work=work,
        derived=work / "normal-ui/DerivedData", result=None if mode == "build" else work / "normal-ui/engineering-test.xcresult",
        methods=(ENGINEERING_METHOD,) if mode == "test" else (), allowance=60 if mode == "test" else None,
        timeout={"build": 240, "test": 180, "summary": 30}[mode], phaseSeconds={"build": 450, "test": 345, "summary": 90}[mode])


def engineering_document(body, limit=65536):
    need(type(body) is bytes and 0 < len(body) <= limit, "engineering-json-bound")
    value = json.loads(body.decode("utf-8", "strict"), object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(Refused("engineering-json-number")))
    need(type(value) is dict, "engineering-json-object")
    return value


def engineering_context(request):
    """Same host/owner and file limits; an independent, exact environment map."""
    need(request.get("engineering") is True and request["target"] == ARM_TARGET, "engineering-arm-only")
    environment = os.environ
    source = environment.get("TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE", "")
    repository = environment.get("GITHUB_REPOSITORY", "")
    need(re.fullmatch(r"[0-9a-f]{40}", source) and environment.get("GITHUB_SHA") == source
         and environment.get("TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE") == source
         and environment.get("TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB") == "github-hosted-macos26-arm64"
         and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
         and environment.get("GITHUB_EVENT_NAME") == "push" and environment.get("GITHUB_REF") == ENGINEERING_REF
         and environment.get("GITHUB_WORKFLOW_SHA") == source
         and environment.get("GITHUB_WORKFLOW_REF") == repository + "/" + ENGINEERING_WORKFLOW + "@" + ENGINEERING_REF
         and all(re.fullmatch(r"[1-9][0-9]{0,19}", environment.get(key, "")) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")),
         "engineering-source-workflow-binding")
    import resource
    need(sys.platform == "darwin" and platform.machine() == "arm64" and platform.mac_ver()[0].startswith("26.")
         and environment.get("DEVELOPER_DIR") == DEVELOPER, "engineering-host-developer")
    file_limit = normal_file_limit(request["phase"], resource.getrlimit(resource.RLIMIT_FSIZE))
    import pwd
    account = pwd.getpwuid(os.getuid())
    need(os.getuid() > 0 and os.getuid() == os.geteuid() == account.pw_uid
         and os.getgid() == os.getegid() == account.pw_gid and account.pw_name == "runner"
         and account.pw_dir == "/Users/runner" and os.stat("/dev/console").st_uid == os.getuid(), "engineering-console-account")
    root = Path(__file__).absolute().parents[2]
    compiler = Path(environment.get("MRK_DESKTOP_CI_ROOT", ""))
    need(str(root) == "/Users/runner/work/mobile-release-kit/mobile-release-kit" and Path.cwd() == root
         and environment.get("GITHUB_WORKSPACE") == str(root)
         and environment.get("MRK_MACOS_WORK") == str(request["work"])
         and compiler.parent == request["work"].parent
         and re.fullmatch(r"mrk-desktop-foundation-[A-Za-z0-9_]{8}", compiler.name)
         and environment.get("TMPDIR") == str(request["work"] / "normal-ui/tmp") + "/", "engineering-owned-input-paths")
    for directory in (request["work"], compiler):
        fd = open_directory(directory)
        try:
            value = os.fstat(fd)
            need(value.st_uid == os.getuid() and value.st_gid == os.getgid() and stat.S_IMODE(value.st_mode) == 0o700
                 and full9(os.stat(directory, follow_symlinks=False)) == full9(value), "engineering-private-owned-root")
        finally:
            os.close(fd)
    request["compiler"] = compiler
    request["binding"] = {"sourceSha": source, "workflowSha": source, "workflowPath": ENGINEERING_WORKFLOW,
        "workflowRef": environment["GITHUB_WORKFLOW_REF"], "runId": environment["GITHUB_RUN_ID"],
        "attempt": environment["GITHUB_RUN_ATTEMPT"], "engineeringWork": str(request["work"])}
    clean = {key: environment[key] for key in ("PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "TZ",
        "DEVELOPER_DIR", "TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB", "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE",
        "TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE")}
    need(all(clean[key] == value for key, value in {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/Users/runner",
         "USER": "runner", "LOGNAME": "runner", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TZ": "UTC"}.items()),
         "engineering-clean-environment")
    # Xcode forwards only this fixed, source-admitted fixture path to XCTest.
    # The application itself receives its own literal whitelist in Swift.
    clean["TEST_RUNNER_MRK_ENGINEERING_UI_WORK"] = str(request["work"])
    return root, source, clean, file_limit


def engineering_compile_receipt(value, binding, phase, *, compiled=None):
    need(phase in ENGINEERING_CHECKS, "engineering-compiler-phase")
    expected = {"schemaVersion": 1, "scope": ENGINEERING_COMPILE_EVIDENCE, "phase": phase, "status": "passed",
        **binding, "platform": "macos", "rust": ENGINEERING_RUST, "node": "v24.20.0",
        "checks": [{"check": name, "exitCode": 0} for name in ENGINEERING_CHECKS[phase]]}
    if phase == "compile":
        need(type(compiled) is dict and set(compiled) == {"relativePath", "bytes", "sha256"}
             and compiled["relativePath"] == "target/engineering-main/" + ENGINEERING_EXECUTABLE
             and type(compiled["bytes"]) is int and 0 < compiled["bytes"] <= ENGINEERING_MAIN_BYTES
             and type(compiled["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", compiled["sha256"]),
             "engineering-compiled-original-receipt")
        expected["compiledMain"] = compiled
    else:
        need(compiled is None, "engineering-acquire-has-no-binary")
    # JSON serialization distinguishes bool/float from the exact integer fields.
    need(type(value) is dict and encoded(value) == encoded(expected), "engineering-complete-compiler-receipt")


def engineering_source_state(phase, binding):
    original = phase.call("engineering-source-identity", ["/usr/bin/git", "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null", "rev-parse", "HEAD", "HEAD^{tree}"], 15, 1024)
    need(original.returncode == 0 and original.stdout == (binding["sourceSha"] + "\n" + binding["sourceTree"] + "\n").encode(),
         "engineering-source-identity")
    unchanged = phase.call("engineering-source-clean", ["/usr/bin/git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
        "diff", "--quiet", "--no-ext-diff", "--no-textconv", "HEAD", "--"], 15, 1024)
    need(unchanged.returncode == 0 and unchanged.stdout == b"", "engineering-source-modified")
    return normal_source_state(phase, binding["sourceSha"])


class EngineeringInputs:
    """Fixed fixture inputs, not an execution owner or a caller-supplied packager.

    All runtime files are admitted against the original stager manifest. Critical
    originals stay open through the original command; every other bounded read
    consumes its own original once. Failed closes cannot yield a positive receipt.
    """
    def __init__(self, phase, request):
        self.phase, self.request = phase, request
        self.work, self.compiler = request["work"], request["compiler"]
        self.held, self.closed = {}, False
        self.runtime_roster = self.app_roster = None

    def read(self, path, limit, *, keep=True, collect=True):
        path = Path(path)
        need(path not in self.held, "engineering-original-duplicate")
        parent = open_directory(path.parent)
        fd = None
        try:
            parent_identity = full9(os.fstat(parent))
            need(stat.S_ISDIR(parent_identity[2]) and not parent_identity[2] & 0o022, "engineering-input-parent")
            fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            body, identity, digest = original_body(fd, limit, collect=collect)
            need(identity[3] == os.getuid() and identity[4] == os.getgid() and not identity[2] & 0o022
                 and full9(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == identity, "engineering-input-original")
            if keep:
                self.held[path] = (fd, parent, parent_identity[:5], identity, digest, limit)
                fd = parent = None
            return body, identity, digest
        finally:
            try:
                if fd is not None:
                    os.close(fd)
            finally:
                if parent is not None:
                    os.close(parent)

    def __enter__(self):
        try:
            context = engineering_document(self.read(self.compiler / "context.json", 65536)[0])
            public = engineering_document(self.read(self.compiler / "public-bindings.json", 1024 * 1024)[0], 1024 * 1024)
            binding = self.request["binding"]
            need(all(context.get(key) == value for key, value in binding.items())
                 and context.get("root") == str(self.compiler) and context.get("source") == str(self.phase.root)
                 and context.get("platform") == "macos" and context.get("executionScope") == ENGINEERING_SCOPE
                 and type(context.get("sourceTree")) is str and re.fullmatch(r"[0-9a-f]{40}", context["sourceTree"]),
                 "engineering-compiler-context")
            workflow = self.read(self.phase.root / ENGINEERING_WORKFLOW, 128 * 1024)[2]
            binding = {**binding, "sourceTree": context["sourceTree"], "workflowSha256": workflow}
            need(all(context.get(key) == value and public.get(key) == value for key, value in binding.items())
                 and public.get("scope") == ENGINEERING_COMPILE_EVIDENCE and public.get("platform") == "macos",
                 "engineering-public-source-bindings")
            self.binding = binding
            for name in ("acquire", "compile"):
                body, _, digest = self.read(self.compiler / (name + "-checks.json"), 16384)
                value = engineering_document(body)
                compiled = value.get("compiledMain") if name == "compile" else None
                engineering_compile_receipt(value, binding, name, compiled=compiled)
                if name == "compile":
                    self.compile_digest = digest
                    self.compiled = compiled
            self.binary = self.compiler / ("target/engineering-main/" + ENGINEERING_EXECUTABLE)
            _, binary_identity, binary_digest = self.read(self.binary, ENGINEERING_MAIN_BYTES, collect=False)
            need(binary_identity[2] & 0o111 and (binary_identity[6], binary_digest) == (self.compiled["bytes"], self.compiled["sha256"]),
                 "engineering-compiled-main-executable")
            plist_body = self.read(self.phase.root / ENGINEERING_PLIST, 4096)[0]
            self.plist_body = plist_body
            metadata = plist(plist_body)
            need(metadata.get("CFBundleIdentifier") == ENGINEERING_IDENTIFIER
                 and metadata.get("CFBundleExecutable") == ENGINEERING_EXECUTABLE
                 and metadata.get("CFBundleName") == "Mobile Release Kit" and metadata.get("CFBundlePackageType") == "APPL",
                 "engineering-fixed-plist")
            description = engineering_document(self.read(self.work / "runtime-description.json", 65536)[0])
            result_body, _, self.runtime_result_digest = self.read(self.work / "runtime-result.json", 65536)
            result = engineering_document(result_body)
            expected = dict(description, qualification="current-source-staged-no-native-execution")
            need(description.get("qualification") == "current-source-description-only-not-build-or-install-authority"
                 and encoded(result) == encoded(expected) and result.get("target") == ARM_TARGET
                 and result.get("supplierOrigin") == "fresh-public-source"
                 and result.get("supplierReceiptSha256") == "2f9cf013c0598b08e89fd9b26d1d74d8ab08be2c22c152ae27cb3219139cd81d"
                 and result.get("supplierProfile") == "mrk-macos-cpython-source-supplier-v1"
                 and result.get("pythonVersion") == "3.14.7" and result.get("gil") is True
                 and not any(key in result for key in ("signedRuntimeBindingSha256", "signedPythonSha256", "signingReceiptSha256")),
                 "engineering-fresh-current-runtime")
            manifest_body, _, self.runtime_manifest_digest = self.read(self.work / "runtime/manifest.json", 1024 * 1024)
            manifest = engineering_document(manifest_body, 1024 * 1024)
            need(set(manifest) == {"schemaVersion", "protocol", "coreVersion", "target", "coreSha256", "protocolSha256", "inventorySha256", "files"}
                 and type(manifest["schemaVersion"]) is int and manifest["schemaVersion"] == 1
                 and type(manifest["protocol"]) is int and manifest["protocol"] == 1 and manifest["target"] == ARM_TARGET
                 and result.get("successorManifestSha256") == self.runtime_manifest_digest
                 and all(manifest[key] == result.get(key) for key in ("inventorySha256", "coreSha256", "protocolSha256")),
                 "engineering-runtime-manifest")
            rows = manifest["files"]
            need(type(rows) is list and 0 < len(rows) <= 2048, "engineering-runtime-roster-bound")
            expected_files = {}
            for row in rows:
                need(type(row) is dict and set(row) == {"path", "sha256", "size"}
                     and type(row["path"]) is str and 0 < len(row["path"].encode()) <= 1024
                     and all(part not in ("", ".", "..") for part in row["path"].split("/"))
                     and "\\" not in row["path"] and "\x00" not in row["path"] and row["path"] != "manifest.json"
                     and row["path"] not in expected_files and type(row["sha256"]) is str
                     and re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                     and type(row["size"]) is int and 0 <= row["size"] <= 512 * 1024 * 1024,
                     "engineering-runtime-file-row")
                expected_files[row["path"]] = row
            need(list(expected_files) == sorted(expected_files)
                 and sha(json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()) == manifest["inventorySha256"]
                 and {"core.zip", "engine_bootstrap.py", "python/bin/python3"} <= set(expected_files)
                 and expected_files["core.zip"]["sha256"] == manifest["coreSha256"]
                 and sum(row["size"] for row in rows) <= 512 * 1024 * 1024, "engineering-runtime-complete-inventory")
            self.runtime_files = expected_files
            self.runtime_roster = self.scan(self.work / "runtime", runtime=True)
            need(set(self.runtime_roster["files"]) == set(expected_files) | {"manifest.json"}, "engineering-runtime-extra-or-missing")
            for name in ("python/bin/python3", "core.zip", "engine_bootstrap.py"):
                self.read(self.work / "runtime" / name, 512 * 1024 * 1024, collect=False)
            bootstrap = self.read(self.phase.root / "desktop/engine_bootstrap.py", 65536)[2]
            protocol = self.read(self.phase.root / "src/mobile_release/_desktop_engine.py", 512 * 1024)[2]
            need(bootstrap == public.get("bootstrapSha256") == expected_files["engine_bootstrap.py"]["sha256"]
                 and protocol == manifest["protocolSha256"], "engineering-current-bootstrap-protocol")
            if self.request["phase"] != "build":
                self.admit_app()
                self.require_prior("engineering-build.command-admission.json", "build")
            return self
        except BaseException:
            try:
                self.close()
            except BaseException:
                pass
            raise

    def scan(self, root, *, runtime):
        files, directories = {}, {}
        total = 0
        root_fd = open_directory(root)
        def walk(fd, prefix, depth):
            nonlocal total
            self.phase.clock.check()
            identity = full9(os.fstat(fd))
            need(depth <= 24 and identity[3] == os.getuid() and identity[4] == os.getgid()
                 and stat.S_IMODE(identity[2]) == 0o555 and len(files) + len(directories) < 4096, "engineering-readonly-directory")
            directories[prefix] = decimal(identity)
            with os.scandir(fd) as entries:
                names = []
                for entry in entries:
                    names.append(entry.name)
                    need(len(names) <= 2048 and len(names) + len(files) + len(directories) <= 4096, "engineering-tree-count")
            for name in sorted(names):
                need(name not in ("", ".", "..") and "/" not in name, "engineering-tree-component")
                relative = name if not prefix else prefix + "/" + name
                need(len(relative.encode()) <= 1024, "engineering-tree-path")
                named = full9(os.stat(name, dir_fd=fd, follow_symlinks=False))
                directory = stat.S_ISDIR(named[2])
                need(directory or stat.S_ISREG(named[2]), "engineering-no-link-or-special-input")
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_DIRECTORY if directory else os.O_NONBLOCK), dir_fd=fd)
                try:
                    need(full9(os.fstat(child)) == named, "engineering-tree-original")
                    if directory:
                        walk(child, relative, depth + 1)
                    else:
                        _, identity, digest = original_body(child, 512 * 1024 * 1024 if runtime else ENGINEERING_MAIN_BYTES)
                        need(identity[3] == os.getuid() and identity[4] == os.getgid()
                             and stat.S_IMODE(identity[2]) == (0o555 if relative == ("python/bin/python3" if runtime else "Contents/MacOS/" + ENGINEERING_EXECUTABLE) else 0o444),
                             "engineering-readonly-file")
                        total += identity[6]
                        need(total <= (512 * 1024 * 1024 if runtime else ENGINEERING_MAIN_BYTES + 1024 * 1024 + 4096), "engineering-tree-bytes")
                        if runtime and relative != "manifest.json":
                            row = self.runtime_files.get(relative)
                            need(row is not None and (identity[6], digest) == (row["size"], row["sha256"]), "engineering-runtime-file-correspondence")
                        files[relative] = [decimal(identity), digest]
                    need(full9(os.stat(name, dir_fd=fd, follow_symlinks=False)) == named, "engineering-tree-named-post")
                finally:
                    os.close(child)
            need(full9(os.fstat(fd)) == tuple(int(v) for v in directories[prefix]),
                 "engineering-tree-directory-post")
        try:
            walk(root_fd, "", 0)
            need(full9(os.stat(root, follow_symlinks=False)) == full9(os.fstat(root_fd)), "engineering-tree-root-post")
        finally:
            os.close(root_fd)
        return {"files": files, "directories": directories}

    def admit_app(self):
        app = self.work / ENGINEERING_APP
        self.app_roster = self.scan(app, runtime=False)
        need(set(self.app_roster["files"]) == {"Contents/Info.plist", "Contents/MacOS/" + ENGINEERING_EXECUTABLE, "Contents/_CodeSignature/CodeResources"}
             and set(self.app_roster["directories"]) == {"", "Contents", "Contents/MacOS", "Contents/Resources", "Contents/_CodeSignature"}, "engineering-app-exact-roster")
        need(self.read(app / "Contents/Info.plist", 4096)[0] == self.plist_body, "engineering-app-plist-bytes")
        self.read(app / ("Contents/MacOS/" + ENGINEERING_EXECUTABLE), ENGINEERING_MAIN_BYTES, collect=False)
        self.read(app / "Contents/_CodeSignature/CodeResources", 1024 * 1024, collect=False)

    def facts(self):
        return {**self.binding, "compilerRoot": str(self.compiler), "target": ARM_TARGET,
            "compilerReceiptSha256": self.compile_digest, "runtimeResultSha256": self.runtime_result_digest,
            "runtimeManifestSha256": self.runtime_manifest_digest, "runtimeRosterSha256": sha(encoded(self.runtime_roster)),
            "applicationRosterSha256": sha(encoded(self.app_roster)),
            "compilerBinarySha256": self.held[self.binary][4]}

    def require_prior(self, name, mode):
        body = self.read(self.work / "normal-ui" / name, 32768)[0]
        value = engineering_document(body)
        need(value.get("scope") == "engineering-main-original-command-admission-only" and value.get("phase") == mode
             and all(value.get(key) == item for key, item in self.facts().items())
             and value.get("originalReturncode") == 0 and type(value.get("originalReturncode")) is int
             and all(value.get(key) is True for key in ("sourcePrePostMatched", "inputPrePostMatched", "inputOriginalClosesCompleted", "originalCommandReturned")),
             "engineering-prior-original-admission")
        return value, sha(body)

    def check(self):
        need(not self.closed, "engineering-inputs-closed")
        for path, (fd, parent, parent_identity, identity, digest, limit) in self.held.items():
            self.phase.clock.check()
            named_parent = open_directory(path.parent)
            try:
                need(full9(os.fstat(named_parent))[:5] == full9(os.fstat(parent))[:5] == parent_identity
                     and full9(os.stat(path.name, dir_fd=named_parent, follow_symlinks=False)) == identity
                     and original_body(fd, limit)[1:] == (identity, digest), "engineering-held-input-pre-post")
            finally:
                os.close(named_parent)
        need(self.scan(self.work / "runtime", runtime=True) == self.runtime_roster, "engineering-runtime-pre-post")
        if self.app_roster is not None:
            need(self.scan(self.work / ENGINEERING_APP, runtime=False) == self.app_roster, "engineering-app-pre-post")

    def close(self):
        if self.closed:
            return
        self.closed = True
        failure = None
        while self.held:
            _, (fd, parent, _, _, _, _) = self.held.popitem()
            for original in (fd, parent):
                try:
                    os.close(original)
                except BaseException as error:
                    if failure is None:
                        failure = error
        if failure is not None:
            raise failure

    def __exit__(self, kind, value, traceback):
        try:
            self.close()
        except BaseException:
            if kind is None:
                raise
        return False


def engineering_assemble(phase, inputs):
    """One exclusive fixed app from the admitted actual debug-main original."""
    app = inputs.work / ENGINEERING_APP
    need(not os.path.lexists(app), "engineering-fresh-app-required")
    app.mkdir(mode=0o700)
    (app / "Contents").mkdir(mode=0o700)
    (app / "Contents/MacOS").mkdir(mode=0o700)
    # Tauri macOS resource_dir canonicalizes MacOS/../Resources during setup,
    # before the main window exists. This fixed empty directory is not a second
    # runtime: development inputs still come only from the admitted external tree.
    (app / "Contents/Resources").mkdir(mode=0o700)
    exclusive_output(app / "Contents/Info.plist", inputs.plist_body, 4096)
    source_fd, _, _, source_identity, source_digest, _ = inputs.held[inputs.binary]
    output = app / ("Contents/MacOS/" + ENGINEERING_EXECUTABLE)
    fd = os.open(output, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o700)
    try:
        offset = 0
        while offset < source_identity[6]:
            phase.clock.check()
            block = os.pread(source_fd, min(65536, source_identity[6] - offset), offset)
            need(bool(block), "engineering-main-copy-short")
            used = 0
            while used < len(block):
                count = os.write(fd, block[used:])
                need(type(count) is int and 0 < count <= len(block) - used, "engineering-main-copy-write")
                used += count
            offset += len(block)
        os.fsync(fd)
        _, identity, digest = original_body(fd, ENGINEERING_MAIN_BYTES)
        need(identity[6] == source_identity[6] and digest == source_digest
             and full9(os.stat(output, follow_symlinks=False)) == identity
             and original_body(source_fd, ENGINEERING_MAIN_BYTES)[1:] == (source_identity, source_digest), "engineering-main-copy-correspondence")
    finally:
        os.close(fd)
    for role, command in (
        ("engineering-ad-hoc-sign", ["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", "--identifier", ENGINEERING_IDENTIFIER, str(app)]),
        ("engineering-verify-app", ["/usr/bin/codesign", "--verify", "--strict", str(app)]),
    ):
        original = phase.call(role, command, 30)
        if original.returncode != 0:
            raise NativeQueryFailure(original)
    # No executable payload, entitlement, helper or writer other than this main.
    for name in ("Contents/Info.plist", "Contents/_CodeSignature/CodeResources"):
        os.chmod(app / name, 0o444, follow_symlinks=False)
    os.chmod(output, 0o555, follow_symlinks=False)
    for name in ("Contents/MacOS", "Contents/Resources", "Contents/_CodeSignature", "Contents", ""):
        os.chmod(app / name, 0o555, follow_symlinks=False)
    inputs.admit_app()


def engineering_ui_markers(stdout):
    need(type(stdout) is bytes and 0 < len(stdout) <= 1024 * 1024 and stdout.endswith(b"\n"), "engineering-test-output-bound")
    text = stdout.decode("utf-8", "strict")
    lines = text.splitlines()
    selected = "-[MRKNormalAppUITests.NormalAppUITests testEngineeringMainCatalogueAndQuit]"
    attempts = [line for line in lines if line.startswith("Test Case ")]
    need(len(attempts) == 2 and attempts[0] == "Test Case '" + selected + "' started."
         and re.fullmatch(r"Test Case '" + re.escape(selected) + r"' passed \([0-9]+(?:\.[0-9]+)? seconds\)\.", attempts[1])
         and lines.count(ENGINEERING_MARKER) == 1
         and sum(line.startswith("MRK_MACOS_ENGINEERING_MAIN_UI=") for line in lines) == 1
         and all(token not in text for token in ("MRK_MACOS_UI_FAILURE_CLEANUP=", "MRK_MACOS_UI_ORIGINAL=", "MRK_MACOS_ENTRY_UI=", "MRK_MACOS_NORMAL_UI="))
         and lines.index(attempts[0]) < lines.index(ENGINEERING_MARKER) < lines.index(attempts[1]), "engineering-one-original-terminal-case")
    return True


def engineering_ui_result(stdout, summary_body):
    engineering_ui_markers(stdout)
    summary = engineering_document(summary_body, 262144)
    counts = {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0}
    need(all(type(summary.get(key)) is int and summary[key] == value for key, value in counts.items()), "engineering-exact-one-passing-test")
    return {"testIdentifier": ENGINEERING_METHOD, "testCounts": counts, "nativeSummarySha256": sha(summary_body),
        "sameOriginalNormalQuitObserved": True, "cleanExitStatus": None, "allWorkerFinality": "not-established",
        "fullUIQualified": False, "productReady": False}


def execute_engineering_phase(phase, request, source, file_limit):
    mode, derived, result = request["phase"], request["derived"], request["result"]
    final = None
    with EngineeringInputs(phase, request) as inputs:
        need(inputs.binding["sourceSha"] == source, "engineering-source-handoff")
        before = engineering_source_state(phase, inputs.binding)
        if mode == "build":
            need(not os.path.lexists(derived), "fresh-derived-data-required")
            engineering_assemble(phase, inputs)
            values = {}
            for key, name, arguments in TOOLCHAIN_QUERIES:
                original = phase.call("normal-toolchain-" + key, list(arguments), 15, 4096)
                if original.returncode != 0:
                    raise NativeQueryFailure(original)
                values[key] = original.stdout
            normal_toolchain(values)
            for key, name, _ in TOOLCHAIN_QUERIES:
                phase.clock.check()
                exclusive_output(derived.parent / name, values[key], 4096)
            original = phase.call("normal-ui-build", normal_build_arguments(derived), 240)
            receipt = derived.parent / "engineering-build.command-admission.json"
            extra = {}
        elif mode == "test":
            verification = phase.call("engineering-verify-app", ["/usr/bin/codesign", "--verify", "--strict", str(inputs.work / ENGINEERING_APP)], 30)
            if verification.returncode != 0:
                raise NativeQueryFailure(verification)
            original, products = run_admitted_test(phase.call, derived, result, (ENGINEERING_METHOD,), 60, 180, engineering=True)
            terminal = engineering_ui_markers(original.stdout) if original.returncode == 0 else False
            exclusive_output(derived.parent / "engineering-test.stdout", original.stdout, 1024 * 1024, allow_empty=True)
            exclusive_output(derived.parent / "engineering-test.stderr", original.stderr, 1024 * 1024, allow_empty=True)
            extra = {"sameOriginalNormalQuitObserved": terminal, "generatedRunnerOriginalClosesCompleted": products["originalClosesCompleted"],
                "generatedRunnerOriginalPrePostMatched": products["originalProductsPrePostMatched"],
                "runnerAdmission": products, "testStdoutSha256": sha(original.stdout), "testStderrSha256": sha(original.stderr)}
            receipt = derived.parent / "engineering-test.runner-admission.json"
        else:
            need(mode == "summary", "engineering-fixed-phase")
            prior, prior_digest = inputs.require_prior("engineering-test.runner-admission.json", "test")
            need(all(prior.get(key) is True for key in ("sameOriginalNormalQuitObserved", "generatedRunnerOriginalClosesCompleted", "generatedRunnerOriginalPrePostMatched")),
                 "engineering-original-test-terminal-required")
            stdout, _, stdout_digest = inputs.read(derived.parent / "engineering-test.stdout", 1024 * 1024)
            _, _, stderr_digest = inputs.read(derived.parent / "engineering-test.stderr", 1024 * 1024)
            need(stdout_digest == prior.get("testStdoutSha256") and stderr_digest == prior.get("testStderrSha256"), "engineering-original-test-output")
            engineering_ui_markers(stdout)
            observed = os.stat(result, follow_symlinks=False)
            need(stat.S_ISDIR(observed.st_mode) and observed.st_uid == os.getuid() and not observed.st_mode & 0o022, "engineering-result-directory")
            original = phase.call("normal-ui-summary", ["/usr/bin/xcrun", "xcresulttool", "get", "test-results", "summary", "--path", str(result), "--compact"], 30, 262144)
            extra = {"testAdmissionSha256": prior_digest}
            if original.returncode == 0:
                final = engineering_ui_result(stdout, original.stdout)
            receipt = derived.parent / "engineering-summary.command-admission.json"
        inputs.check()
        need(engineering_source_state(phase, inputs.binding) == before, "engineering-source-pre-post")
        facts = {**inputs.facts(), **extra, "schemaVersion": 1, "scope": "engineering-main-original-command-admission-only",
            "phase": mode, "originalReturncode": original.returncode, "sourcePrePostMatched": True,
            "inputPrePostMatched": True, "originalCommandReturned": True}
    facts.update(inputOriginalClosesCompleted=True, commands=phase.records, fileLimitBytes=list(file_limit),
        phaseClock=phase.clock.before_publication(), receiptPolicy="exclusive0600-readback-consuming-close")
    exclusive_output(receipt, encoded(facts) + b"\n", 32768)
    phase.clock.check()
    if final is not None:
        value = {**{key: facts[key] for key in (*ENGINEERING_BINDINGS, "compilerRoot", "target", "compilerReceiptSha256",
                     "runtimeResultSha256", "runtimeManifestSha256", "runtimeRosterSha256", "applicationRosterSha256",
                     "compilerBinarySha256", "testAdmissionSha256")},
            **final, "schemaVersion": 1, "scope": "engineering-main-ui-smoke-only", "status": "passed",
            "sourcePrePostMatched": True, "inputPrePostMatched": True, "inputOriginalClosesCompleted": True,
            "generatedRunnerOriginalClosesCompleted": True, "originalCommandsReturned": True,
            "summaryAdmissionSha256": sha(encoded(facts) + b"\n"), "originalWrapperZeroRequired": True}
        exclusive_output(derived.parent / "engineering-smoke.json", encoded(value) + b"\n", 16384)
        phase.clock.check()
    return original


def engineering_native_failure(request, original, owner, records, *, query=False):
    """Supplement the same returned failure; diagnostic refusal cannot replace it."""
    failure = normal_admission_failure("diagnostic", NativeQueryFailure(original), owner, records)
    try:
        need(type(query) is bool and request.get("engineering") is True
             and request["phase"] in ("build", "test", "summary"), "engineering-diagnostic-request")
        phase = "query" if query else request["phase"]
        selection = None if phase in ("build", "query") else request["result"].name
        unavailable = failure_base(phase, selection, original, engineering=True)
        try:
            value = normal_failure_diagnostics(phase, selection, original, engineering=True)
            need(len(encoded(value)) + 1 <= 4096, "normal-diagnostic-output-bound")
        except Exception:
            value = unavailable
        combined = {**failure, "nativeDiagnostics": value}
        if len(encoded(combined)) + 1 <= 16384:
            return combined
    except Exception:
        # Includes original admission: verify-app query output may exceed4KiB.
        # Preserve the generic facts and exact primary nonzero, never enlarge caps.
        pass
    return failure


def publish_engineering_failure(request, failure):
    """Best-effort closed facts only; never cleanup or completion authority."""
    try:
        need(request.get("engineering") is True and request["phase"] in ("build", "test", "summary")
             and request["derived"] == request["work"] / "normal-ui/DerivedData", "engineering-diagnostic-request")
        body = encoded(failure) + b"\n"
        need(len(body) <= 16384, "engineering-diagnostic-bound")
        work_fd = open_directory(request["work"])
        try:
            work = full9(os.fstat(work_fd))
            need(stat.S_IMODE(work[2]) == 0o700 and work[3:5] == (os.getuid(), os.getgid())
                 and full9(os.stat(request["work"], follow_symlinks=False)) == work, "engineering-diagnostic-work")
            normal_fd = os.open("normal-ui", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=work_fd)
            try:
                normal = full9(os.fstat(normal_fd))
                need(stat.S_IMODE(normal[2]) == 0o700 and normal[3:5] == (os.getuid(), os.getgid())
                     and full9(os.stat(request["derived"].parent, follow_symlinks=False)) == normal, "engineering-diagnostic-output-root")
                exclusive_output(request["derived"].parent / ("engineering-" + request["phase"] + ".failure-diagnostics.json"), body, 16384)
                for path, fd, before in ((request["work"], work_fd, work), (request["derived"].parent, normal_fd, normal)):
                    need(full9(os.fstat(fd))[:6] == before[:6]
                         and full9(os.stat(path, follow_symlinks=False))[:6] == before[:6], "engineering-diagnostic-original-changed")
            finally:
                os.close(normal_fd)
        finally:
            os.close(work_fd)
    except Exception:
        # Preserve the original nonzero/unknown. Do not retry or expose raw errors.
        try:
            sys.stderr.write("engineering-failure-diagnostic-publication-failed\n")
        except Exception:
            pass


def main():
    owner = None
    phase = None
    request = None
    engineering = False
    records = []
    stage = "request"
    try:
        started = time.monotonic_ns()  # Includes CLI/context/loader admission in this one phase.
        engineering = bool(sys.argv[1:]) and sys.argv[1] in ENGINEERING_MODES
        request = (engineering_request(sys.argv[1:], os.environ.get("TMPDIR", "")) if engineering
                   else normal_request(sys.argv[1:], os.environ.get("TMPDIR", "")))
        clock = PhaseClock(request["phaseSeconds"], started=started)
        stage = "context"
        root, source, environment, file_limit = engineering_context(request) if engineering else normal_context(request)
        stage = "loader"
        owner = load_normal_owner(root)
        stage = "phase"
        phase = (NormalPhase(owner, environment, root, clock, retain_nonzero=True)
                 if request.get("outputData") is True or request.get("androidPositive") is True or request.get("iosUnsigned") is True else NormalPhase(owner, environment, root, clock))
        records = phase.records
        try:
            stage = "execute"
            original = (execute_engineering_phase(phase, request, source, file_limit) if engineering
                        else execute_normal_phase(phase, request, source, file_limit))
        except NativeQueryFailure as failure:
            # No subsequent query/build/source command after the original failed query.
            stage = "diagnostic"
            if engineering:
                publish_engineering_failure(request, engineering_native_failure(
                    request, failure.original, owner, records, query=True))
                sys.stdout.buffer.write(failure.original.stdout)
                sys.stderr.buffer.write(failure.original.stderr)
                sys.stdout.buffer.flush()
                sys.stderr.buffer.flush()
            elif request.get("androidPositive") is True:
                publish_android_signed_failure(request, stage, failure.original.returncode)
            else:
                publish_failure_diagnostics(request, failure.original, query=True)
            stage = "finalize"
            clock.finish()
            return failure.original.returncode
        if original.returncode != 0:
            stage = "diagnostic"
            if request.get("androidPositive") is True:
                publish_android_signed_failure(request, stage, original.returncode)
            elif engineering:
                publish_engineering_failure(request, engineering_native_failure(request, original, owner, records))
            else:
                publish_failure_diagnostics(request, original, role=records[-1]["role"] if request.get("outputData") is True else None)
        stage = "publication"
        sys.stdout.buffer.write(original.stdout)  # Workflow keeps these full originals PRIVATE.
        sys.stderr.buffer.write(original.stderr)
        sys.stdout.buffer.flush()
        sys.stderr.buffer.flush()
        stage = "finalize"
        clock.finish()
        return original.returncode
    except BaseException as error:
        if phase is not None:
            phase.clock.failed = True
        if request is not None and request.get("iosUnsigned") is True:
            code = phase.first_nonzero.returncode if phase is not None and phase.first_nonzero is not None else 1
            try:
                # Optional closed diagnostics cannot replace an original return or
                # create a usable result after failed/unknown publication/close.
                need(phase is not None, "ios-unsigned-diagnostic-context-admitted")
                failure = normal_admission_failure(stage, error, owner, records)
                body = encoded(failure) + b"\n"
                need(len(body) <= 16384, "ios-unsigned-failure-bound")
                stem = SUMMARY_STEMS[request["result"].name] if request["phase"] == "summary" else request["result"].stem
                exclusive_output(request["derived"].parent / (stem + ".failure-diagnostics.json"), body, 16384)
            except BaseException:
                pass
            return code
        if request is not None and request.get("androidPositive") is True:
            code = phase.first_nonzero.returncode if phase is not None and phase.first_nonzero is not None else 1
            try:
                publish_android_signed_failure(request, stage, code)
            except BaseException:
                pass  # No optional diagnostic may replace this original failure.
            return code
        if request is not None and request.get("outputData") is True and phase is not None and phase.first_nonzero is not None:
            retained_status = phase.first_nonzero.returncode
            try:
                failure = normal_admission_failure(stage, error, owner, records)
                body = encoded(classify_normal_admission_failure(encoded(failure))) + b"\n"
                exclusive_output(request["derived"].parent / "output-data-test.failure-diagnostics.json", body, 4096)
                sys.stderr.write(encoded(failure).decode("ascii") + "\n")
            except BaseException:
                pass  # Optional diagnostics cannot mask the FIRST admitted native nonzero.
            return retained_status
        failure = normal_admission_failure(stage, error, owner, records)
        if engineering and request is not None:
            publish_engineering_failure(request, failure)
        if request is not None and request.get("outputData") is True and phase is not None:
            try:
                body = encoded(classify_normal_admission_failure(encoded(failure))) + b"\n"
                exclusive_output(request["derived"].parent / "output-data-test.failure-diagnostics.json", body, 4096)
            except BaseException:
                pass  # Diagnostic publication cannot replace the original failure.
        sys.stderr.write(encoded(failure).decode("ascii") + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
