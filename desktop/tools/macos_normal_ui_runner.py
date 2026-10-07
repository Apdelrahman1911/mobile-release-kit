#!/usr/bin/env python3
"""Fixed generated Mac UI-runner admission; no application launch or repair here.

Import is inert. The diagnostic uses its existing original-command owner; the
normal workflow CLI admits fixed build/summary phases and six exact test selections.
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

DEVELOPER = "/Applications/Xcode.app/Contents/Developer"
ARM_TARGET = "aarch64-apple-darwin"
INTEL_TARGET = "x86_64-apple-darwin"
PROJECT = "desktop/native/macos-normal-ui/MRKNormalAppUI.xcodeproj"
LOADER = "desktop/tools/macos_aqua_qualification.py"
LOADER_SHA = "ee80e0c4234ed35533603e71c6939b55cabf1b4322a64956f56021aed0a323b6"
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


def xcode_test_arguments(manifest, result, methods, allowance, *, target=ARM_TARGET):
    machine, _ = normal_target_data(target)
    need(tuple(methods) != (PACKAGED_METHOD,) or target == ARM_TARGET, "fixed-packaged-test-target")
    need(tuple(methods) == (PACKAGED_METHOD,) or
         any(tuple(methods) == tuple(CLASS + method for method in selection[0])
             and allowance == selection[1] for selection in NORMAL_SELECTIONS.values()),
         "fixed-test-selection")
    need(allowance in (60, 300) and (tuple(methods) != (PACKAGED_METHOD,) or allowance == 60), "test-allowance")
    return ["/usr/bin/xcodebuild", "test-without-building", "-xctestrun", str(manifest),
        "-destination", "platform=macOS,arch=" + machine, "-destination-timeout", "15",
        "-resultBundlePath", str(result), *["-only-testing:" + method for method in methods],
        "-parallel-testing-enabled", "NO", "-test-timeouts-enabled", "YES",
        "-default-test-execution-time-allowance", str(allowance),
        "-maximum-test-execution-time-allowance", str(allowance), "-disableAutomaticPackageResolution"]


def run_admitted_test(call, derived, result, methods, allowance, timeout, *, target=ARM_TARGET):
    normal_target_data(target)
    need(tuple(methods) != (PACKAGED_METHOD,) or target == ARM_TARGET, "fixed-packaged-test-target")
    need(not os.path.lexists(result), "fresh-xcresult-required")
    with RunnerProducts(derived) as products:
        facts = products.admit(call)  # Actual generated runner, BEFORE xcodebuild can request any app.
        command = xcode_test_arguments(products.products / products.manifest, result, methods, allowance, target=target)
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



SUMMARY_STEMS = {"test.xcresult": "summary", "project-test.xcresult": "project-summary",
    "persistence-test.xcresult": "persistence-summary", "diagnostics-test.xcresult": "diagnostics-summary",
    "saved-checks-test.xcresult": "saved-checks-summary",
    "workflow-refusal-test.xcresult": "workflow-refusal-summary"}
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
    def __init__(self, owner, environment, root, clock):
        self.owner, self.environment, self.root, self.clock = owner, environment, root, clock
        self.records = []

    def call(self, role, argv, seconds, limit=1024 * 1024):
        try:
            actual = self.clock.allowance(seconds)
            value = self.owner.run_owned(argv, environ=self.environment, cwd=self.root, timeout=actual,
                                        capture=True, text=False, output_limit=limit)
            original_command(value, argv, limit)
            self.records.append({"role": role, "returncode": value.returncode,
                "timeoutSeconds": actual, "roleCapSeconds": seconds, "outputLimitBytes": limit,
                "argvSha256": sha(encoded(argv)), "stdoutBytes": len(value.stdout), "stdoutSha256": sha(value.stdout),
                "stderrBytes": len(value.stderr), "stderrSha256": sha(value.stderr)})
            self.clock.check()
            return value
        except BaseException:
            self.clock.failed = True
            raise


def exclusive_output(path, body, limit):
    """No overwrite/reopen; original complete readback and consuming close."""
    need(type(body) is bytes and 0 < len(body) <= limit, "normal-output-bound")
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


class NativeQueryFailure(Exception):
    """One validated returned nonzero query; no later build/query is dispatched."""
    def __init__(self, original):
        super().__init__("normal-toolchain-original-nonzero")
        self.original = original


def execute_normal_phase(phase, request, source, file_limit):
    """Original owner/source checks shared by fixed build, test and summary."""
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
        receipt = result.parent / (SUMMARY_STEMS[result.name] + ".command-admission.json")
    else:
        need(mode == "test", "normal-phase-selection")
        original, facts = run_admitted_test(phase.call, derived, result, request["methods"],
                                            request["allowance"], request["timeout"], target=target)
        facts.update(originalTestReturncode=original.returncode, normalPhase="test", resultBundle=result.name)
        if original.returncode == 0 and result.name == "project-test.xcresult":
            project_markers = normal_project_markers(original.stdout)
            facts["projectFieldAndEditMarkersObserved"] = project_markers
            facts["androidToolSourceBrowseMarkerObserved"] = project_markers
        if original.returncode == 0 and result.name == "workflow-refusal-test.xcresult":
            facts["managedWorkflowRefusalMarkerObserved"] = normal_workflow_refusal_markers(original.stdout)
        receipt = result.with_suffix(".runner-admission.json")
    need(normal_source_state(phase, source) == before, "normal-ui-source-pre-post")
    facts.update(target=target, sourceCommit=source, sourceRosterSha256=sha(encoded(before)), sourcePrePostMatched=True,
                 originalCommandReturned=True, commands=phase.records, fileLimitBytes=list(file_limit),
                 phaseClock=phase.clock.before_publication(), receiptPolicy="exclusive0600-readback-consuming-close")
    exclusive_output(receipt, encoded(facts) + b"\n", 32768)
    phase.clock.check()  # Includes actual original receipt close, never inferred from a persisted flag.
    return original


def failure_base(phase, selection, original):
    need(phase in ("build", "test", "summary", "query")
         and (selection is None if phase in ("build", "query") else selection in NORMAL_SELECTIONS),
         "normal-diagnostic-selection")
    cap = 4096 if phase == "query" else 262144 if phase == "summary" else 1024 * 1024
    need(type(original) is subprocess.CompletedProcess and type(original.returncode) is int
         and 1 <= original.returncode <= 255 and type(original.stdout) is bytes and type(original.stderr) is bytes
         and len(original.stdout) + len(original.stderr) <= cap, "normal-diagnostic-original")
    return {"schemaVersion": 1, "scope": "normal-macos-ui-failure-diagnostic-only", "phase": phase,
        "selection": selection, "originalReturncode": original.returncode,
        "stdoutBytes": len(original.stdout), "stdoutSha256": sha(original.stdout),
        "stderrBytes": len(original.stderr), "stderrSha256": sha(original.stderr),
        "status": "unavailable", "findingsTruncated": False, "errorCodes": [], "sourceFailures": [],
        "queryObservations": [], "requireObservations": [], "dashboardReadiness": None,
        "markers": {"selectedCaseStarted": False, "selectedCaseFailed": False,
            "testExecuteFailed": False, "testingFailed": False, "xcodebuildError": False}}


def normal_failure_diagnostics(phase, selection, original):
    """Whole-original bounded text to fixed observations, never raw error/reason text."""
    value = failure_base(phase, selection, original)
    domains = {domain.encode("ascii"): domain for domain in (
        "NSCocoaErrorDomain", "NSPOSIXErrorDomain", "NSOSStatusErrorDomain", "NSMachErrorDomain",
        "XCTestErrorDomain", "XCTRunnerErrorDomain", "com.apple.dt.xctest.error",
        "IDETestOperationsObserverErrorDomain", "IDEFoundationErrorDomain", "RBSRequestErrorDomain",
        "RBSServiceErrorDomain", "FBSOpenApplicationServiceErrorDomain", "FBSOpenApplicationErrorDomain",
        "IXUserPresentableErrorDomain")}
    codes = (rb"(?:\A|(?<=[ \t\r\n({\x5b]))Error[ \t]{1,8}Domain=(" + b"|".join(re.escape(x) for x in domains)
             + rb")[ \t]{1,8}Code=(-?(?:0|[1-9][0-9]{0,9}))(?=\Z|[ \t\r\n,;\"')}\x5d])")
    methods = NORMAL_SELECTIONS[selection][0] if selection is not None else ()
    method_pattern = b"|".join(re.escape(m.encode("ascii")) for m in methods)
    case = rb"-\[MRKNormalAppUITests\.NormalAppUITests (?:" + method_pattern + rb")\]"
    locations = (rb"(?:\A|(?<=[/ \t\r\n]))NormalAppUITests\.swift:([1-9][0-9]{0,4})"
                 rb"(?::([1-9][0-9]{0,3}))?:[ \t]{1,8}error:[ \t]{1,8}"
                 rb"-\[MRKNormalAppUITests\.NormalAppUITests (" + method_pattern + rb")\][ \t]{0,8}:")
    markers = {"testExecuteFailed": rb"(?m)^\*\* TEST EXECUTE FAILED \*\*\r?$",
               "testingFailed": rb"(?m)^Testing failed:", "xcodebuildError": rb"(?m)^xcodebuild: error:"}
    if methods:
        markers.update(selectedCaseStarted=rb"(?m)^Test Case '" + case + rb"' started\.\r?$",
            selectedCaseFailed=rb"(?m)^Test Case '" + case + rb"' failed(?: \([0-9]{1,6}(?:\.[0-9]{1,9})? seconds\))?\.\r?$")
    query = (rb"MRK_MACOS_NORMAL_(RENDERER|DASHBOARD)_QUERY=observation="
             rb"(initial|identifier|title|label|value|placeholderValue|containingSameStaticText)"
             rb";matches=([0-5]);exceedsFour=([01]);nonAtomic=1")

    # The existing ordinary basic case alone owns this diagnostic grammar.
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

    def retain(key, finding, maximum, distinct=True):
        if not distinct or finding not in value[key]:
            if len(value[key]) < maximum:
                value[key].append(finding)
            else:
                value["findingsTruncated"] = True

    for stream, body in (("stdout", original.stdout), ("stderr", original.stderr)):
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
    if (dashboard_eligible and not require_invalid and dashboard_candidates == 1
            and dashboard_candidate is not None and len(value["requireObservations"]) == 1
            and original.stderr.count(b"MRK_MACOS_PACKAGED_REQUIRE_FAILURE") == 0):
        site = value["requireObservations"][0]
        if (site["check"] == "condition" and site["line"] == dashboard_candidate["line"]
                and dashboard_candidate["stream"] == "stdout"):
            value["dashboardReadiness"] = dashboard_candidate
    value["status"] = ("unavailable" if require_invalid else "classified" if any(value[key]
        for key in ("errorCodes", "sourceFailures", "queryObservations", "requireObservations")) else "unclassified")
    need(len(encoded(value)) + 1 <= 4096, "normal-diagnostic-output-bound")
    return value


def publish_failure_diagnostics(request, original, *, query=False):
    phase = "query" if query else request["phase"]
    selection = None if phase in ("build", "query") else request["result"].name
    # Validate before formatting: caller must already hold a genuine returned nonzero original.
    unavailable = failure_base(phase, selection, original)
    try:
        value = normal_failure_diagnostics(phase, selection, original)
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
    "verify-generated-runner", "generated-runner-entitlements", "one-admitted-ui-test",
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
    return {"schemaVersion": 1, "scope": "generated-ui-runner-refused", "productReady": False,
        "error": "runner-admission-or-owner-error", "stage": stage, "exceptionClass": label,
        "sourceFrames": frames, "commands": records, "ownerFailure": owner_failure, "unknownStateRetained": True}


def classify_normal_admission_failure(body):
    """A whole exception-only JSON record, never a search of private native logs."""
    unavailable = {"schemaVersion": 1, "scope": "normal-macos-ui-admission-diagnostic-only",
        "status": "unavailable", "nativeSuccessInferred": False, "productReady": False,
        "unknownStateRetained": True}
    try:
        value = document(body)
        need(set(value) == {"schemaVersion", "scope", "productReady", "error", "stage", "exceptionClass",
             "sourceFrames", "commands", "ownerFailure", "unknownStateRetained"}, "admission-fields")
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
    return root, source, environment, file_limit


def main():
    owner = None
    phase = None
    records = []
    stage = "request"
    try:
        started = time.monotonic_ns()  # Includes CLI/context/loader admission in this one phase.
        request = normal_request(sys.argv[1:], os.environ.get("TMPDIR", ""))
        clock = PhaseClock(request["phaseSeconds"], started=started)
        stage = "context"
        root, source, environment, file_limit = normal_context(request)
        stage = "loader"
        owner = load_normal_owner(root)
        stage = "phase"
        phase = NormalPhase(owner, environment, root, clock)
        records = phase.records
        try:
            stage = "execute"
            original = execute_normal_phase(phase, request, source, file_limit)
        except NativeQueryFailure as failure:
            # No subsequent query/build/source command after the original failed query.
            stage = "diagnostic"
            publish_failure_diagnostics(request, failure.original, query=True)
            stage = "finalize"
            clock.finish()
            return failure.original.returncode
        if original.returncode != 0:
            stage = "diagnostic"
            publish_failure_diagnostics(request, original)
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
        failure = normal_admission_failure(stage, error, owner, records)
        sys.stderr.write(encoded(failure).decode("ascii") + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
