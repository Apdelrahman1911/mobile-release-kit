#!/usr/bin/env python3
"""Fixed generated Mac UI-runner admission; no application launch or repair here.

Import is inert. The diagnostic uses its existing original-command owner; the
normal workflow CLI is confined to its five existing exact test selections.
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

DEVELOPER = "/Applications/Xcode.app/Contents/Developer"
PROJECT = "desktop/native/macos-normal-ui/MRKNormalAppUI.xcodeproj"
LOADER = "desktop/tools/macos_aqua_qualification.py"
LOADER_SHA = "bd069b9e7150113a671b7165ca89adf36e42328656a223a2f2d077197d583e25"
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
    "project-test.xcresult": (("testSyntheticProjectLocalEditsAndImages",), 300, 420),
    "persistence-test.xcresult": (("testSyntheticPersistentCredentials",), 300, 420),
    "diagnostics-test.xcresult": (("testSyntheticProjectBuildToolDiagnostics",), 300, 420),
    "saved-checks-test.xcresult": (("testSyntheticProjectSavedOfflineChecks",
                                  "testSyntheticProjectEmptyBuildInputInspection"), 300, 720),
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


def xcode_test_arguments(manifest, result, methods, allowance):
    need(tuple(methods) == (PACKAGED_METHOD,) or
         any(tuple(methods) == tuple(CLASS + method for method in selection[0])
             and allowance == selection[1] for selection in NORMAL_SELECTIONS.values()),
         "fixed-test-selection")
    need(allowance in (60, 300) and (tuple(methods) != (PACKAGED_METHOD,) or allowance == 60), "test-allowance")
    return ["/usr/bin/xcodebuild", "test-without-building", "-xctestrun", str(manifest),
        "-destination", "platform=macOS,arch=arm64", "-destination-timeout", "15",
        "-resultBundlePath", str(result), *["-only-testing:" + method for method in methods],
        "-parallel-testing-enabled", "NO", "-test-timeouts-enabled", "YES",
        "-default-test-execution-time-allowance", str(allowance),
        "-maximum-test-execution-time-allowance", str(allowance), "-disableAutomaticPackageResolution"]


def run_admitted_test(call, derived, result, methods, allowance, timeout):
    need(not os.path.lexists(result), "fresh-xcresult-required")
    with RunnerProducts(derived) as products:
        facts = products.admit(call)  # Actual generated runner, BEFORE xcodebuild can request any app.
        command = xcode_test_arguments(products.products / products.manifest, result, methods, allowance)
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


def normal_cli_arguments(arguments):
    need(len(arguments) in (25, 26) and arguments[0] == "test-without-building", "normal-fixed-command")
    # Reconstruct the complete old argv; no extra xcodebuild switch may escape.
    need(arguments[11] == "-derivedDataPath" and arguments[13] == "-resultBundlePath", "normal-product-arguments")
    derived, result = Path(arguments[12]), Path(arguments[14])
    need(result.name in NORMAL_SELECTIONS, "normal-existing-selection")
    methods, allowance, timeout = NORMAL_SELECTIONS[result.name]
    expected = ["test-without-building", "-project", PROJECT, "-scheme", "MRKNormalAppUI",
        "-configuration", "Debug", "-destination", "platform=macOS,arch=arm64",
        "-destination-timeout", "15", "-derivedDataPath", str(derived),
        "-resultBundlePath", str(result), *["-only-testing:" + CLASS + method for method in methods],
        "-parallel-testing-enabled", "NO", "-test-timeouts-enabled", "YES",
        "-default-test-execution-time-allowance", str(allowance),
        "-maximum-test-execution-time-allowance", str(allowance), "-disableAutomaticPackageResolution"]
    need(arguments == expected and result.parent == derived.parent and derived.name == "DerivedData"
         and derived.parent.name == "normal-ui", "normal-exact-command")
    return derived, result, tuple(CLASS + method for method in methods), allowance, timeout


def main():
    owner = None
    records = []
    try:
        derived, result, methods, allowance, timeout = normal_cli_arguments(sys.argv[1:])
        source = os.environ.get("TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE", "")
        need(re.fullmatch(r"[0-9a-f]{40}", source)
             and os.environ.get("TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE") == source
             and os.environ.get("TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB") == "github-hosted-macos26-arm64",
             "normal-same-build-only")
        import resource  # Native CLI only; DATA/source import remains portable.
        need(sys.platform == "darwin" and platform.machine() == "arm64" and platform.mac_ver()[0].startswith("26.")
             and os.environ.get("DEVELOPER_DIR") == DEVELOPER and resource.getrlimit(resource.RLIMIT_FSIZE) == (1024**3, 1024**3),
             "normal-host-developer-file-budget")
        import pwd
        account = pwd.getpwuid(os.getuid())
        need(os.getuid() > 0 and os.getuid() == os.geteuid() == account.pw_uid
             and os.getgid() == os.getegid() == account.pw_gid and account.pw_name == "runner"
             and account.pw_dir == "/Users/runner" and os.stat("/dev/console").st_uid == os.getuid(), "normal-console-account")
        root = Path(__file__).absolute().parents[2]
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
        loader_fd = os.open(root / LOADER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            _, loader_identity, loader_digest = original_body(loader_fd, 1024 * 1024)
            need(loader_digest == LOADER_SHA, "normal-owner-loader-pin")
            spec = importlib.util.spec_from_file_location("mrk_normal_ui_owner_loader", root / LOADER)
            need(spec is not None and spec.loader is not None, "normal-owner-loader")
            loader = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(loader)
            owner = loader.load_owner(root)
            need(full9(os.stat(root / LOADER, follow_symlinks=False)) == loader_identity
                 and original_body(loader_fd, 1024 * 1024)[1:] == (loader_identity, loader_digest), "normal-owner-loader-changed")
        finally:
            os.close(loader_fd)

        def call(role, argv, seconds):
            original = owner.run_owned(argv, environ=environment, cwd=root, timeout=seconds,
                capture=True, text=False, output_limit=1024 * 1024)
            need(type(original) is subprocess.CompletedProcess and type(original.args) is list and original.args == argv
                 and type(original.returncode) is int and 0 <= original.returncode <= 255
                 and type(original.stdout) is bytes and type(original.stderr) is bytes
                 and len(original.stdout) + len(original.stderr) <= 1024 * 1024, "normal-original-command")
            records.append({"role": role, "returncode": original.returncode,
                "stdoutBytes": len(original.stdout), "stdoutSha256": sha(original.stdout),
                "stderrBytes": len(original.stderr), "stderrSha256": sha(original.stderr)})
            return original

        source_arguments = ["/usr/bin/git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
            "ls-tree", "-r", "-z", "--full-tree", source, "--", "desktop/native/macos-normal-ui",
            "desktop/tools/macos_normal_ui_runner.py"]
        def source_state():
            original = call("normal-ui-source-roster", source_arguments, 15)
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
                fd = os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    body, identity, digest = original_body(fd, 1024 * 1024, collect=True)
                    need(hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest() == blob.decode("ascii")
                         and full9(os.stat(root / name, follow_symlinks=False)) == identity, "normal-ui-source-correspondence")
                    facts[name] = [decimal(identity), digest]
                finally:
                    os.close(fd)
            need("desktop/tools/macos_normal_ui_runner.py" in facts
                 and "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift" in facts,
                 "normal-ui-source-complete")
            return facts

        before = source_state()
        original, facts = run_admitted_test(call, derived, result, methods, allowance, timeout)
        need(source_state() == before, "normal-ui-source-pre-post")
        facts.update(sourceCommit=source, sourceRosterSha256=sha(encoded(before)), sourcePrePostMatched=True,
                     originalCommandReturned=True, originalTestReturncode=original.returncode, commands=records)
        receipt = result.with_suffix(".runner-admission.json")
        fd = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            body = encoded(facts) + b"\n"
            need(len(body) <= 32768, "normal-runner-receipt-bound")
            offset = 0
            while offset < len(body):
                count = os.write(fd, body[offset:])
                need(count > 0, "normal-runner-receipt-write")
                offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
        sys.stdout.buffer.write(original.stdout)
        sys.stderr.buffer.write(original.stderr)
        return original.returncode
    except BaseException as error:
        failure = {"schemaVersion": 1, "scope": "generated-ui-runner-refused", "productReady": False,
            "error": str(error) if type(error) is Refused else "runner-admission-or-owner-error",
            "commands": records, "unknownStateRetained": True}
        if owner is not None and isinstance(error, (owner.ProcessError, owner.ProcessInterrupted)):
            failure["ownerFailure"] = {name: value if type(value := getattr(error, attribute, None)) is bool else None
                for name, attribute in (("dispatched", "dispatched"), ("contained", "contained"), ("cleanupComplete", "cleanup_complete"))}
        sys.stderr.write(encoded(failure).decode("ascii") + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
