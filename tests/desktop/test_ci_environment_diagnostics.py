"""Pure environment-native CI contracts. No tools, native owners or fixture IO.

All receipt values below are deliberately invented consumer data, never native
evidence. They exercise the strict parser and scope boundary without executing
main(), real platform admission, Cargo, subprocesses, cleanup or the hosted fixture.
CLT preparation tests use invented host/metadata values and replace every lstat.
"""
from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[2]
HELPER = SOURCE / "desktop/tools/ci_foundation.py"
SPEC = importlib.util.spec_from_file_location("desktop_environment_ci_contract", HELPER)
assert SPEC is not None and SPEC.loader is not None
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)

CLT_SPEC = importlib.util.spec_from_file_location("desktop_environment_clt_metadata", SOURCE / "desktop/tools/environment_macos_clt.py")
assert CLT_SPEC is not None and CLT_SPEC.loader is not None
clt = importlib.util.module_from_spec(CLT_SPEC)
CLT_SPEC.loader.exec_module(clt)


def binding_environment(event: str = "push", attempt: str = "1", *, platform: str = "linux", ref: str | None = None) -> dict:
    ref = helper.ENVIRONMENT_NATIVE_REF if ref is None else ref
    return {"MRK_DESKTOP_HOSTED_CHECKS": helper.ENVIRONMENT_NATIVE_SCOPE,
        "GITHUB_SHA": "1" * 40, "GITHUB_WORKFLOW_SHA": "1" * 40,
        "GITHUB_REPOSITORY": "synthetic/project", "GITHUB_RUN_ID": "23", "GITHUB_RUN_ATTEMPT": attempt,
        "GITHUB_REF": ref, "GITHUB_EVENT_NAME": event, "MRK_DESKTOP_PLATFORM": platform,
        "GITHUB_WORKFLOW_REF": f"synthetic/project/{helper.ENVIRONMENT_NATIVE_WORKFLOW}@{ref}",
        "MRK_EXPECTED_SHA": "1" * 40, "MRK_PUSH_EVENT_AFTER": "1" * 40}


def native_inputs(platform: str = "linux", *, ref: str | None = None) -> dict:
    binding = helper.environment_native_binding(binding_environment(platform=platform, ref=ref))
    core = [{"path": name, "sha256": "4" * 64, "size": 1} for name in helper.GTK_CORE_PATHS]
    names = {helper.ENVIRONMENT_NATIVE_WORKFLOW, "desktop/tools/ci_foundation.py", "desktop/environment_bootstrap.py",
        "desktop/src-tauri/Cargo.toml", "desktop/src-tauri/Cargo.lock", "desktop/src-tauri/build.rs",
        "desktop/src-tauri/src/lib.rs", "desktop/src-tauri/src/environment_diagnostics_owner.rs",
        "desktop/src-tauri/src/environment_diagnostics_hosted_tests.rs", "tests/native_desktop_environment.py",
        "tests/workflow/command_bootstrap_fixture.py", *("src/" + name for name in helper.GTK_CORE_PATHS)}
    sources = [{"path": name, "sha256": "4" * 64, "size": 1} for name in sorted(names)]
    root, source = "/synthetic/tmp/mrk-desktop-foundation-environment-23-1", "/synthetic/source"
    directories = {name: {"device": "1", "inode": str(index + 2), "mode": stat.S_IFDIR | 0o700,
                           "uid": 1001, "gid": 1001}
                   for index, name in enumerate(("root", "source", "cwd", *helper.ENVIRONMENT_NATIVE_DIRECTORIES))}
    host = {"system": "Linux", "kernelRelease": "6.11.0", "machine": "x86_64", "nonRoot": True,
            "imageOS": "ubuntu24", "imageVersion": "20260917.1"}
    if platform == "macos":
        host.update(system="Darwin", kernelRelease="25.0.0", machine="arm64", imageOS="macos26-arm64")
    return {"schemaVersion": 1, "scope": helper.ENVIRONMENT_NATIVE_SCOPE, **binding,
        "root": root, "source": source, "cwd": source + "/desktop", "python": "/synthetic/python",
        "sourceTree": "2" * 40, "platform": platform, "target": helper.TARGETS[platform],
        "sourceFiles": sources, "coreFiles": core, "workflowSha256": "4" * 64,
        "bootstrapSha256": "4" * 64, "coreZipSha256": "5" * 64, "coreZipBytes": 4096,
        "pythonSha256": "6" * 64, "pythonBytes": 8192, "originalDirectories": directories, "observedHost": host}


def native_context(platform: str = "linux") -> dict:
    inputs = native_inputs(platform)
    return {**{key: inputs[key] for key in ("root", "source", "python", "platform", "sourceSha", "sourceTree",
        "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt", "repository", "event", "ref")},
        "executionScope": helper.ENVIRONMENT_NATIVE_SCOPE, "environmentInputs": inputs,
        "environmentInputsSha256": hashlib.sha256(helper.canonical_json(inputs) + b"\n").hexdigest()}


def compiler_messages(platform: str = "linux") -> tuple[dict, dict]:
    context = native_context(platform)
    executable = f"{context['root']}/target/{helper.TARGETS[platform]}/debug/deps/mobile_release_desktop-0123456789abcdef"
    artifact = {"reason": "compiler-artifact", "target": {"kind": ["lib"], "name": "mobile_release_desktop",
        "src_path": context["source"] + "/desktop/src-tauri/src/lib.rs"},
        "manifest_path": context["source"] + "/desktop/src-tauri/Cargo.toml",
        "profile": {"test": True, "debug_assertions": True}, "features": ["development-runtime"],
        "fresh": False, "executable": executable}
    return artifact, {"reason": "build-finished", "success": True}


def compile_invocation(platform: str = "linux") -> tuple[dict, dict, dict]:
    context = native_context(platform)
    summary = {"size": 4096, "sha256": "7" * 64, "invocationSha256": "8" * 64, "messagesSha256": "9" * 64}
    receipt = helper.environment_phase_value(context, "compile", compiled=summary)
    invocation = {"schemaVersion": 1, "scope": helper.ENVIRONMENT_NATIVE_SCOPE,
        "inputsSha256": context["environmentInputsSha256"],
        **{key: context[key] for key in ("sourceSha", "sourceTree", "platform")},
        "target": helper.TARGETS[platform], "path": compiler_messages(platform)[0]["executable"], **summary,
        "identity": {"device": "1", "inode": "99", "mode": stat.S_IFREG | 0o700, "uid": 1001,
                     "gid": 1001, "size": 4096, "mtimeNs": 123456},
        "compileReceiptSha256": hashlib.sha256(helper.canonical_json(receipt) + b"\n").hexdigest()}
    return context, receipt, invocation


def projection_value(platform: str, case: str) -> dict:
    mobile = "ios" if case == "R2" or case == "R3" and platform == "macos" else "android"
    context = {"projectId": "synthetic-project", "draftRevision": 1, "baselineGeneration": 1,
               "platform": mobile, "operation": "build"}
    late = case in {"L5", "L6a", "L6b", "L6c", "L7", "wait-nonzero", "reader-late-stderr"}
    reason = {"L1": "cancelled", "L2": "timed-out", "L3a": "cancelled", "L3b": "context-changed", "L3c": "document-lost",
        "L3d": "shutdown", "L4": "command-failed", "L5": "timed-out", "L6a": "timed-out", "L6b": "timed-out",
        "L6c": "timed-out", "L7": "cleanup-unknown", "wait-nonzero": "protocol-error", "reader-late-stderr": "protocol-error"}.get(case, "none")
    projection = {"runId": "a" * 32, "ownerGeneration": "b" * 32, "context": context,
        "phase": "retained-unknown" if late else "settled", "finality": "unknown" if late else "settled",
        "reason": reason, "outcome": "failed" if late else "unavailable", "result": None}
    if case in {"L1", "L2", "wait-nonzero"}:
        projection["outcome"] = "cancelled" if case == "L1" else "timed-out" if case == "L2" else "failed"
        return projection
    real = case in {"R1", "R2", "R3"}
    shim = case in {"L3a", "L3b", "L3c", "L3d", "L4", "L5"}
    host_mismatch = platform == "linux" and mobile == "ios"
    roles = (("developer-selection",) if platform == "macos" else ()) + (("git", "java", "javac") if mobile == "android" else ("git", "xcode"))
    checks = []
    for role in roles:
        baseline = ({"kind": "workflow-reference", "version": "21", "build": None} if role in {"java", "javac"} else
            {"kind": "exact-pin", "version": "26.3", "build": "17C529"} if role == "xcode" else
            {"kind": "no-local-policy", "version": None, "build": None})
        state, why = "not-run", "platform-disabled"
        if host_mismatch:
            why = "host-mismatch"
        elif real or shim and role == "developer-selection":
            state, why = "completed", "observed"
        elif shim:
            state, why = ("attempted", "cancelled" if case.startswith("L3") else "command-incomplete") if role == "git" else ("not-run", "stopped")
        version = {"git": "2.43.0", "java": "21.0.5", "javac": "21.0.5", "xcode": "26.3"}.get(role) if state == "completed" else None
        checks.append({"id": role, "state": state, "reason": why, "version": version,
            "build": "17C529" if role == "xcode" and state == "completed" else None,
            "returnCode": 0 if state == "completed" else None, "baseline": baseline,
            "assessment": "match" if role == "xcode" and state == "completed" else "no-local-policy" if version is not None else "not-assessed",
            "help": "Inert consumer help text, not native evidence."})
    attempts = sum(row["state"] != "not-run" for row in checks)
    outcome = ("cancelled" if case.startswith("L3") else "partial" if platform == "macos" else "failed") if shim else "complete" if attempts else "unavailable"
    result = {"schemaVersion": 1, "policyVersion": "environment-diagnostics-v1", "context": context, "hostPlatform": platform,
        "outcome": outcome, "checks": checks, "commandsAttempted": attempts,
        "lifetime": {"complete": True, "fatal": False, "contained": True, "commandDispatched": attempts > 0,
            "commands": attempts, "inputClosed": True, "handlersRestored": True, "toolDescriptorsClosed": True,
            "stopObserved": "cancelled" if case.startswith("L3") else "none"},
        "assurance": {"basis": "local-tool-observation", "toolsAttempted": attempts > 0, "projectCodeExecuted": False,
            "projectFilesRead": False, "repositoryObserved": False, "sdkInspected": False, "credentialsRead": False,
            "storeContacted": False, "dependencyCompleteness": "unknown", "releaseReadiness": "unknown", "toolCacheEffects": "possible"}}
    projection["result"] = result
    projection["outcome"] = "timed-out" if case in {"L5", "L6a", "L6b", "L6c"} else "failed" if late else outcome
    if case == "reader-no-eof":
        projection.update(phase="stopping", finality="pending")
    return projection


def original_resources(case: str) -> dict:
    absent, negative = case in {"L1", "L2"}, case == "L7"
    native = {"startup": {"attempted": not absent, "returned": not absent, "failed": False},
        "inspection": {"joined": case != "L1", "failed": False, "retained": False},
        "acquisition": {"joined": not absent, "failed": False, "retained": False},
        "child": {"present": not absent, "waited": not absent, "code": None if absent else 0, "waitFailed": False},
        **{role: {"close": "new" if absent else "settled", "retained": False} for role in ("input", "output", "error")},
        "writer": {"joined": True, "failed": False, "end": {"sent": not absent, "closed": not absent, "failed": False}},
        "outputBytes": 0 if absent else 4096, "resourceUnknown": negative, "activeRetained": negative,
        "disabled": negative or case in {"L5", "L6a", "L6b", "L6c"}, "canExit": not negative}
    for role in ("stdout", "stderr"):
        native[role] = {"joined": True, "failed": False, "end": {"frames": 2 if role == "stdout" and not absent else 0,
                        "eof": not absent, "closed": not absent, "failed": False}}
    for role in ("driver", "manager", "observer", "watchdog"):
        receipt = "panic" if negative and role == "driver" else "ok-false" if negative and role in {"observer", "watchdog"} else (
            "ok-true" if role in {"observer", "watchdog"} else "ok-unit")
        native[role] = {"receipt": receipt, "retained": negative and role != "manager"}
    return native


def case_value(platform: str, name: str) -> dict:
    reader, wait = name.startswith("reader-"), name == "wait-nonzero"
    shim = name in {"L3a", "L3b", "L3c", "L3d", "L4", "L5"}
    case = {"id": name, "classification": "synthetic-reader" if reader else "synthetic-wait" if wait else
        "real-source" if name in {"R1", "R2"} else "real-zip" if name == "R3" else
        "expected-driver-loss" if name == "L7" else "synthetic-lifecycle",
        "assertion": "passed", "reason": None, "timing": None,
        "projection": None if name in {"reader-shared-cap", "reader-close-error"} else projection_value("linux" if reader or wait else platform, name),
        "native": None if reader or wait else original_resources(name), "ordinary": [], "reader": None,
        "files": {"controlClosed": True if shim else None, "relayClosed": True if shim else None}}
    if reader:
        case["reader"] = {"outputBytes": 66000 if name == "reader-shared-cap" else 0 if name == "reader-close-error" else 4096,
            "frames": 2 if name == "reader-no-eof" else 0, "eof": True,
            "closed": name != "reader-close-error", "failed": name in {"reader-shared-cap", "reader-late-stderr"},
            "closeCalls": 1, "secondaryFrames": 2 if name == "reader-late-stderr" else 0,
            "secondaryFailed": name == "reader-shared-cap",
            "pendingObserved": name == "reader-no-eof"}
    elif not wait:
        late = name in {"L5", "L6a", "L6b", "L6c"}
        held = name in {"L1", "L2"} or late
        case["timing"] = {"workMs": 6000, "finalityMs": 10000, "heldMs": 100 if held else None,
            "releasedMs": 11000 if late else 6500 if name == "L2" else 200 if held else None,
            "interventionMs": 150 if name.startswith("L3") else None, "unknownMs": 10001 if late else None,
            "returnedMs": 11100 if late else 6600 if name == "L2" else 500}
    if shim:
        common = {"schemaVersion": 1, "case": name, "runId": "a" * 32, "ownerGeneration": "b" * 32,
                  "commandNonce": "c" * 32, "recipeSha256": "d" * 64}
        ready = {**common, "event": "target-ready", "remainingNs": 2 * 10**9, "sourceDelayNs": 10**6}
        settled = {**common, "event": "settled", "intercepts": 1, "readyObserved": True,
            "resultIntegrity": "incomplete", "dispatched": True, "contained": True, "cleanupComplete": True,
            "cWait": 2, "aWait": 0, "cFinish": 2, "aFinish": 0, "targetWait": {"kind": "exit", "code": 0},
            "targetMarker": True, "readersJoined": True, "traceCloses": {"o": True, "c": True, "a": True, "w": True},
            "noNextCall": True, "reason": "cancelled" if name.startswith("L3") else "command-incomplete", "coreCode": 0,
            "stopBeforeWorkNs": 10**9 if name.startswith("L3") else None,
            "capture": {"stdout": 8, "stderr": 0, "limit": 16384, "overflow": False} if name.startswith("L3") else
                       {"stdout": 8192, "stderr": 8193, "limit": 16384, "overflow": True}}
        case["ordinary"] = [ready, settled]
    return case


def native_result(platform: str = "linux") -> tuple[dict, dict, str]:
    context = native_context(platform)
    invocation_digest = "f" * 64
    cases = [case_value(platform, name) for name in helper.ENVIRONMENT_NATIVE_CASES]
    omissions = [{"case": row["id"], "check": check["id"], "reason": check["reason"]}
        for row in cases if row["id"] in {"R1", "R2", "R3"}
        for check in row["projection"]["result"]["checks"] if check["reason"] != "observed"]
    result = {"schemaVersion": 1, "scope": helper.ENVIRONMENT_NATIVE_SCOPE,
        "inputsSha256": context["environmentInputsSha256"], "invocationSha256": invocation_digest,
        **{key: context[key] for key in ("sourceSha", "sourceTree", "platform", "workflowSha", "runId", "attempt")},
        "target": helper.TARGETS[platform], "caseOrder": list(helper.ENVIRONMENT_NATIVE_CASES), "cases": cases,
        "unexecuted": omissions, "classification": "finite-complete-with-expected-driver-loss"}
    return context, result, invocation_digest


def progress_value(context: dict, completed: int = 0) -> dict:
    return {"schemaVersion": 1, "scope": helper.ENVIRONMENT_NATIVE_SCOPE,
        "inputsSha256": context["environmentInputsSha256"], "sourceSha": context["sourceSha"], "platform": context["platform"],
        "classification": "native-not-settled", "completedCases": list(helper.ENVIRONMENT_NATIVE_CASES[:completed]),
        "nextCase": helper.ENVIRONMENT_NATIVE_CASES[completed] if completed < 20 else None,
        "stage": "result" if completed == 20 else "negative-tail" if completed == 19 else "reader", "failureCode": None}


def outer_value(context: dict, code: int = 0) -> dict:
    return {"schemaVersion": 1, "scope": helper.ENVIRONMENT_NATIVE_SCOPE,
        **{key: context[key] for key in ("sourceSha", "platform", "runId", "attempt")}, "originalWait": True,
        "exitCode": code, "outputWritersClosed": True, "statusWriterCloseGate": "original-step-success-required", "fileLimitBytes": 1048576}


class EnvironmentNativeCIContracts(unittest.TestCase):
    def assert_refused(self, action, value) -> None:
        with self.assertRaises(helper.CheckFailure):
            action(value)

    def test_clt_metadata_requires_real_root_owned_fixed_directories_and_git(self) -> None:
        def facts(mode, *, uid=0, gid=0, links=1, size=4096):
            return clt.os.stat_result((mode, 1, 1, links, uid, gid, size, 0, 0, 0))
        for gid in (0, 80):
            clt.validate_directory(facts(stat.S_IFDIR | 0o775, gid=gid), "clt")
        clt.validate_git(facts(stat.S_IFREG | 0o755))
        for value in (facts(stat.S_IFLNK | 0o777), facts(stat.S_IFDIR | 0o755, uid=501),
                      facts(stat.S_IFDIR | 0o757), facts(stat.S_IFDIR | 0o775, gid=20)):
            with self.subTest(directory=value), self.assertRaises(clt.SetupError):
                clt.validate_directory(value, "clt")
        invalid_git = [facts(stat.S_IFDIR | 0o755), facts(stat.S_IFLNK | 0o755),
            facts(stat.S_IFREG | 0o755, uid=501), facts(stat.S_IFREG | 0o755, links=2),
            facts(stat.S_IFREG | 0o755, size=0)]
        invalid_git.extend(facts(stat.S_IFREG | mode) for mode in (0o655, 0o775, 0o757, 0o4755, 0o2755))
        for value in invalid_git:
            with self.subTest(git=value), self.assertRaises(clt.SetupError):
                clt.validate_git(value)

    def test_clt_host_and_ancestors_fail_before_any_later_namespace_read(self) -> None:
        environment = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64", "MRK_DESKTOP_PLATFORM": "macos",
            "MRK_DESKTOP_HOSTED_CHECKS": helper.ENVIRONMENT_NATIVE_SCOPE}
        wrong = [(environment, "Linux", "arm64", 501), (environment, "Darwin", "x86_64", 501),
                 (environment, "Darwin", "arm64", 0), (environment, "Darwin", "arm64", True)]
        wrong.extend(({**environment, key: "unadmitted"}, "Darwin", "arm64", 501) for key in environment)
        with patch.object(clt.os, "lstat", side_effect=AssertionError("no installed namespace read")) as observed:
            for arguments in wrong:
                with self.subTest(arguments=arguments), self.assertRaises(clt.SetupError):
                    clt.inspect_installed(*arguments)
            observed.assert_not_called()
        paths = [path for _stage, path in clt.DIRECTORIES] + [clt.GIT]
        directory = clt.os.stat_result((stat.S_IFDIR | 0o755, 1, 1, 1, 0, 0, 4096, 0, 0, 0))
        executable = clt.os.stat_result((stat.S_IFREG | 0o755, 1, 1, 1, 0, 0, 4096, 0, 0, 0))
        with patch.object(clt.os, "lstat", side_effect=lambda path: executable if path == clt.GIT else directory) as observed:
            clt.inspect_installed(environment, "Darwin", "arm64", 501)
            self.assertEqual([call.args[0] for call in observed.call_args_list], paths)
        for refusal in (FileNotFoundError(), PermissionError(),
                        clt.os.stat_result((stat.S_IFLNK | 0o777, 1, 1, 1, 0, 0, 4096, 0, 0, 0))):
            with patch.object(clt.os, "lstat", side_effect=[directory, refusal]) as observed:
                with self.subTest(refusal=refusal), self.assertRaises(clt.SetupError):
                    clt.inspect_installed(environment, "Darwin", "arm64", 501)
                self.assertEqual([call.args[0] for call in observed.call_args_list], paths[:2])

    def test_complete_clt_lifecycle_keeps_full_xcode_observations_unexecuted(self) -> None:
        context, result, digest = native_result("macos")
        for name in ("R2", "R3"):
            projection = result["cases"][helper.ENVIRONMENT_NATIVE_CASES.index(name)]["projection"]
            terminal = projection["result"]
            xcode = next(row for row in terminal["checks"] if row["id"] == "xcode")
            xcode.update(state="not-run", reason="full-xcode-not-selected", version=None, build=None,
                         returnCode=None, assessment="not-assessed")
            terminal.update(outcome="partial", commandsAttempted=2)
            terminal["lifetime"]["commands"] = 2
            projection["outcome"] = "partial"
            result["unexecuted"].append({"case": name, "check": "xcode", "reason": "full-xcode-not-selected"})
        self.assertEqual(helper.validate_environment_result(result, context, digest), result)
        self.assertTrue(all(row["assertion"] == "passed" for row in result["cases"]))
        missing = deepcopy(result)
        missing["unexecuted"] = []
        self.assert_refused(lambda value: helper.validate_environment_result(value, context, digest), missing)

    def test_scope_is_closed_and_does_not_authorize_historical_or_gui_phases(self) -> None:
        self.assertEqual(helper.ENVIRONMENT_NATIVE_PHASES,
                         ("prepare", "acquire", "compile", "environment-native", "retain"))
        for phase in helper.ENVIRONMENT_NATIVE_PHASES:
            helper.admit_phase(helper.ENVIRONMENT_NATIVE_SCOPE, phase)
        for phase in ("native", "github-tls", "metadata-owner", "workflow-owner", "windows-snapshot", "clean"):
            self.assert_refused(lambda value: helper.admit_phase(helper.ENVIRONMENT_NATIVE_SCOPE, value), phase)
        for platform in ("linux", "macos"):
            helper.admit_platform(helper.ENVIRONMENT_NATIVE_SCOPE, platform)
        self.assert_refused(lambda value: helper.admit_platform(helper.ENVIRONMENT_NATIVE_SCOPE, value), "windows")
        self.assert_refused(lambda value: helper.admit_phase(helper.BOUNDARY_SCOPE, value), "environment-native")

    def test_exact_event_workflow_source_and_failed_job_attempt_are_bound(self) -> None:
        for event in ("push", "workflow_dispatch"):
            for attempt in ("1", "2"):
                self.assertEqual(helper.environment_native_binding(binding_environment(event, attempt))["attempt"], attempt)
        for key, value in (("GITHUB_SHA", "0" * 40), ("GITHUB_WORKFLOW_SHA", "2" * 40),
                ("GITHUB_REF", "refs/heads/main"), ("GITHUB_WORKFLOW_REF", "synthetic/project/other@main"),
                ("GITHUB_RUN_ATTEMPT", "0"), ("GITHUB_RUN_ID", True), ("GITHUB_REPOSITORY", "../project"),
                ("MRK_PUSH_EVENT_AFTER", "3" * 40), ("MRK_DESKTOP_HOSTED_CHECKS", helper.GITHUB_READONLY_SCOPE)):
            with self.subTest(key=key):
                value_env = binding_environment()
                value_env[key] = value
                self.assert_refused(helper.environment_native_binding, value_env)
        dispatch = binding_environment("workflow_dispatch")
        dispatch["MRK_EXPECTED_SHA"] = "3" * 40
        self.assert_refused(helper.environment_native_binding, dispatch)

    def test_mac_only_ref_has_exact_platform_and_workflow_binding_not_prefix_authority(self) -> None:
        old, mac = helper.ENVIRONMENT_NATIVE_REF, helper.ENVIRONMENT_NATIVE_MACOS_REF
        for ref, platform in ((old, "linux"), (old, "macos"), (mac, "macos")):
            for event in ("push", "workflow_dispatch"):
                environment = binding_environment(event, platform=platform, ref=ref)
                self.assertEqual(helper.environment_native_binding(environment)["ref"], ref)
                inputs = native_inputs(platform, ref=ref)
                self.assertEqual(helper.validate_environment_inputs(inputs), inputs)
        for ref, platform in ((mac, "linux"), (old, "windows"), (mac + "-other", "macos"), ("refs/heads/main", "macos")):
            self.assert_refused(helper.environment_native_binding, binding_environment(platform=platform, ref=ref))
            inputs = native_inputs("macos")
            inputs.update(ref=ref, platform=platform, target=helper.TARGETS.get(platform, helper.TARGETS["macos"]),
                workflowRef=f"synthetic/project/{helper.ENVIRONMENT_NATIVE_WORKFLOW}@{ref}")
            self.assert_refused(helper.validate_environment_inputs, inputs)
        for key, wrong in (("GITHUB_REF", []), ("MRK_DESKTOP_PLATFORM", []),
                           ("GITHUB_WORKFLOW_REF", f"synthetic/project/{helper.ENVIRONMENT_NATIVE_WORKFLOW}@{old}")):
            environment = binding_environment(platform="macos", ref=mac)
            environment[key] = wrong
            self.assert_refused(helper.environment_native_binding, environment)
        inputs = native_inputs("macos", ref=mac)
        inputs["workflowRef"] = f"synthetic/project/{helper.ENVIRONMENT_NATIVE_WORKFLOW}@{old}"
        self.assert_refused(helper.validate_environment_inputs, inputs)

    def test_inputs_accept_only_original_host_and_complete_source_zip_correspondence(self) -> None:
        for platform in ("linux", "macos"):
            value = native_inputs(platform)
            self.assertEqual(helper.validate_environment_inputs(value), value)
        mutations = []
        for key, bad in (("schemaVersion", True), ("scope", helper.GITHUB_READONLY_SCOPE), ("platform", []),
                         ("event", []), ("sourceSha", "0" * 40), ("cwd", "/synthetic/other"),
                         ("python", "/synthetic/../python"), ("coreZipBytes", True), ("target", helper.TARGETS["windows"])):
            value = native_inputs()
            value[key] = bad
            mutations.append(value)
        missing = native_inputs()
        missing["sourceFiles"] = [row for row in missing["sourceFiles"] if row["path"] != "tests/native_desktop_environment.py"]
        mutations.append(missing)
        package = native_inputs()
        package["coreFiles"][0]["sha256"] = "f" * 64
        mutations.append(package)
        duplicate = native_inputs()
        duplicate["sourceFiles"].append(deepcopy(duplicate["sourceFiles"][0]))
        mutations.append(duplicate)
        for host_key, bad in (("nonRoot", False), ("machine", "arm64"), ("imageOS", "ubuntu22"), ("kernelRelease", "bad\nvalue")):
            value = native_inputs()
            value["observedHost"][host_key] = bad
            mutations.append(value)
        wrong_mac = native_inputs("macos")
        wrong_mac["observedHost"]["kernelRelease"] = "24.1.0"
        mutations.append(wrong_mac)
        directory = native_inputs()
        directory["originalDirectories"]["root"]["mode"] = stat.S_IFLNK | 0o777
        mutations.append(directory)
        for index, value in enumerate(mutations):
            with self.subTest(index=index):
                self.assert_refused(helper.validate_environment_inputs, value)

    def test_public_binding_excludes_private_paths_inventory_and_capability_claims(self) -> None:
        inputs = native_inputs()
        value = helper.environment_public_bindings(inputs, "e" * 64)
        encoded = helper.canonical_json(value)
        for private in (inputs["root"], inputs["source"], inputs["python"]):
            self.assertNotIn(private.encode(), encoded)
        self.assertEqual(value["coreFiles"], len(helper.GTK_CORE_PATHS))
        self.assertEqual(value["sourceFiles"], len(inputs["sourceFiles"]))
        self.assertEqual(value["notVerified"], list(helper.ENVIRONMENT_NATIVE_NOT_VERIFIED))
        self.assertNotIn("NATIVE_QUALIFIED", value)

    def test_compiler_records_exact_fresh_two_host_artifact_not_glob_or_other_test(self) -> None:
        for platform in ("linux", "macos"):
            context = native_context(platform)
            rows = compiler_messages(platform)
            observed = helper.environment_compiled_test(b"\n".join(helper.canonical_json(row) for row in rows),
                source=Path(context["source"]), root=Path(context["root"]), platform=platform)
            self.assertEqual(str(observed), rows[0]["executable"])
        artifact, finish = compiler_messages()
        mutations = [[artifact], [finish], [artifact, artifact, finish], [artifact, finish, finish],
                     [artifact, {"reason": "build-finished", "success": False}]]
        for key, bad in (("fresh", True), ("features", ["desktop-shell", "development-runtime"]),
                         ("executable", "/synthetic/other/mobile_release_desktop-0123456789abcdef"),
                         ("manifest_path", "/synthetic/other/Cargo.toml")):
            row = deepcopy(artifact)
            row[key] = bad
            mutations.append([row, finish])
        binary = deepcopy(artifact)
        binary["target"]["kind"] = ["bin"]
        mutations.append([binary, finish])
        bool_test = deepcopy(artifact)
        bool_test["profile"]["test"] = 1
        mutations.append([bool_test, finish])
        context = native_context()
        for index, rows in enumerate(mutations):
            with self.subTest(index=index):
                self.assert_refused(lambda raw: helper.environment_compiled_test(raw, source=Path(context["source"]),
                    root=Path(context["root"]), platform="linux"), b"\n".join(helper.canonical_json(row) for row in rows))
        wrong_target = compiler_messages("macos")
        self.assert_refused(lambda raw: helper.environment_compiled_test(raw, source=Path(context["source"]),
            root=Path(context["root"]), platform="linux"), b"\n".join(helper.canonical_json(row) for row in wrong_target))

    def test_invocation_binds_original_identity_compile_receipt_and_no_hash_cycle(self) -> None:
        for platform in ("linux", "macos"):
            context, receipt, invocation = compile_invocation(platform)
            validate = lambda value: helper.validate_environment_invocation(value, context=context,
                compile_receipt=receipt, compile_digest=invocation["compileReceiptSha256"])
            self.assertEqual(validate(invocation), invocation)
            self.assertNotIn("compileReceiptSha256", receipt)
            for key, bad in (("scope", helper.GITHUB_TLS_SCOPE), ("inputsSha256", "0" * 64),
                             ("compileReceiptSha256", "0" * 64), ("sha256", "0" * 64), ("size", True)):
                value = deepcopy(invocation)
                value[key] = bad
                self.assert_refused(validate, value)
            for key, bad in (("uid", 0), ("inode", 2), ("mode", stat.S_IFREG | 0o777), ("size", 8192)):
                value = deepcopy(invocation)
                value["identity"][key] = bad
                self.assert_refused(validate, value)

    def test_clear_native_environment_does_not_inherit_credentials_or_tool_configuration(self) -> None:
        context = native_context("macos")
        with patch.dict(helper.os.environ, {"PATH": "/usr/bin:/bin", "GITHUB_TOKEN": "inert-secret-marker",
                "HTTPS_PROXY": "inert-proxy-marker", "DEVELOPER_DIR": "/unreviewed/xcode",
                "PYTHONPATH": "/unreviewed/python", "JAVA_TOOL_OPTIONS": "unreviewed", "RUSTFLAGS": "unreviewed"}, clear=True):
            observed = helper.environment_native_environment(context)
        for name in ("GITHUB_TOKEN", "HTTPS_PROXY", "DEVELOPER_DIR", "PYTHONPATH", "JAVA_TOOL_OPTIONS", "RUSTFLAGS"):
            self.assertNotIn(name, observed)
        self.assertEqual(observed["MRK_DESKTOP_DEV_PYTHON"], context["python"])
        self.assertEqual(observed["MRK_DESKTOP_DEV_CORE"], context["source"] + "/src")
        self.assertEqual(observed["MRK_ENVIRONMENT_NATIVE_INPUTS"], context["root"] + "/environment-native-inputs.json")
        self.assertEqual(observed["RUNNER_ARCH"], "ARM64")

    def test_bounded_json_rejects_duplicate_fields_nonfinite_and_overbound_data(self) -> None:
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1.1}', b"not-json"):
            self.assert_refused(lambda value: helper.bounded_json(value, 1024), raw)
        self.assert_refused(lambda value: helper.bounded_json(value, 2), b'{"x":1}')

    def test_complete_native_dto_requires_physical_originals_and_last_negative_task(self) -> None:
        for platform in ("linux", "macos"):
            context, result, digest = native_result(platform)
            self.assertEqual(helper.validate_environment_result(result, context, digest), result)
        context, original, digest = native_result()
        index = {name: position for position, name in enumerate(helper.ENVIRONMENT_NATIVE_CASES)}
        mutations = (
            (("cases", index["R1"], "native", "child", "waited"), False),
            (("cases", index["R1"], "native", "stdout", "end", "closed"), False),
            (("cases", index["R1"], "projection", "result", "lifetime", "inputClosed"), False),
            (("cases", index["L3c"], "projection", "reason"), "cancelled"),
            (("cases", index["L3a"], "ordinary", 1, "cFinish"), 0),
            (("cases", index["L3a"], "ordinary", 0, "remainingNs"), 0),
            (("cases", index["L3a"], "ordinary", 1, "stopBeforeWorkNs"), 0),
            (("cases", index["L3a"], "ordinary", 1, "stopBeforeWorkNs"), True),
            (("cases", index["L3a"], "projection", "result", "lifetime", "stopObserved"), "timed-out"),
            (("cases", index["L4"], "ordinary", 1, "capture", "stdout"), 8193),
            (("cases", index["L4"], "ordinary", 1, "stopBeforeWorkNs"), 10**9),
            (("cases", index["L5"], "timing", "unknownMs"), 1),
            (("cases", index["L6c"], "native", "watchdog", "receipt"), "not-joined"),
            (("cases", index["L7"], "native", "driver", "receipt"), "ok-unit"),
            (("cases", index["L7"], "native", "driver", "retained"), False),
            (("cases", index["L7"], "native", "canExit"), True),
            (("cases", index["reader-no-eof"], "reader", "pendingObserved"), False),
            (("cases", index["reader-close-error"], "reader", "closeCalls"), 2),
            (("classification",), "passed"),
            (("invocationSha256",), "0" * 64),
            (("unexecuted",), []),
        )
        for path, bad in mutations:
            with self.subTest(path=path):
                value = deepcopy(original)
                at = value
                for component in path[:-1]:
                    at = at[component]
                at[path[-1]] = bad
                self.assert_refused(lambda result: helper.validate_environment_result(result, context, digest), value)

    def test_no_tool_management_refusals_distinguish_attempts_from_invalid_drafts(self) -> None:
        for platform in ("linux", "macos"):
            for name in ("L6a", "L6b", "L6c", "L7"):
                for attempted in (False, True):
                    with self.subTest(platform=platform, case=name, attempted=attempted):
                        context, result, digest = native_result(platform)
                        projection = result["cases"][helper.ENVIRONMENT_NATIVE_CASES.index(name)]["projection"]
                        if attempted:
                            projection["result"] = projection_value(platform, "R1")["result"]
                            expected = f"Environment {name} no-tool management case attempted tools"
                        else:
                            # Change every reason together: mixed refusal reasons
                            # would fail an earlier DTO consistency check instead.
                            for check in projection["result"]["checks"]:
                                check["reason"] = "invalid-draft"
                            expected = f"Environment {name} no-tool management case did not report platform-disabled"
                        self.assertEqual(helper.validate_environment_projection(projection, platform), projection)
                        with self.assertRaises(helper.CheckFailure) as caught:
                            helper.validate_environment_result(result, context, digest)
                        self.assertEqual(str(caught.exception), expected)

    def test_real_r1_git_refusal_prevents_synthetic_admission_without_fake_relay(self) -> None:
        context, result, digest = native_result()
        r1 = result["cases"][helper.ENVIRONMENT_NATIVE_CASES.index("R1")]["projection"]["result"]
        git = r1["checks"][0]
        git.update(state="not-run", reason="missing-in-supported-lookup", version=None, returnCode=None, assessment="not-assessed")
        r1["commandsAttempted"] -= 1
        r1["lifetime"]["commands"] -= 1
        for index, case in enumerate(result["cases"]):
            if case["id"] in {"L3a", "L3b", "L3c", "L3d", "L4", "L5"}:
                result["cases"][index] = {"id": case["id"], "classification": "synthetic-lifecycle", "assertion": "unexecuted",
                    "reason": "git-not-admitted", "timing": None, "projection": None, "native": None, "ordinary": [], "reader": None,
                    "files": {"controlClosed": None, "relayClosed": None}}
        result["unexecuted"].insert(0, {"case": "R1", "check": "git", "reason": "missing-in-supported-lookup"})
        result["unexecuted"].extend({"case": name, "check": "git", "reason": "git-not-admitted"}
            for name in ("L3a", "L3b", "L3c", "L3d", "L4", "L5"))
        result["classification"] = "finite-incomplete-with-expected-driver-loss"
        self.assertEqual(helper.validate_environment_result(result, context, digest), result)
        stale = deepcopy(result)
        stale["cases"][helper.ENVIRONMENT_NATIVE_CASES.index("L3a")] = case_value("linux", "L3a")
        self.assert_refused(lambda value: helper.validate_environment_result(value, context, digest), stale)
        false_success = deepcopy(result)
        false_success["classification"] = "finite-complete-with-expected-driver-loss"
        self.assert_refused(lambda value: helper.validate_environment_result(value, context, digest), false_success)

    def test_current_l5_refusal_keeps_actual_late_native_receipts_but_not_ordinary_coverage(self) -> None:
        for reason in ("git-not-admitted", "insufficient-work-margin"):
            with self.subTest(reason=reason):
                context, result, digest = native_result()
                case = result["cases"][helper.ENVIRONMENT_NATIVE_CASES.index("L5")]
                case.update(assertion="unexecuted", reason=reason)
                case["ordinary"] = [{"schemaVersion": 1, "case": "L5", "runId": case["projection"]["runId"],
                    "ownerGeneration": case["projection"]["ownerGeneration"], "event": "unexecuted", "intercepts": 0,
                    "readyObserved": False, "observerClosed": True, "noNextCall": True, "reason": reason, "coreCode": 0}]
                if reason == "git-not-admitted":
                    terminal = projection_value("linux", "R1")["result"]
                    terminal["checks"][0].update(state="not-run", reason="missing-in-supported-lookup",
                        version=None, returnCode=None, assessment="not-assessed")
                    terminal["commandsAttempted"] -= 1
                    terminal["lifetime"]["commands"] -= 1
                    case["projection"]["result"] = terminal
                else:
                    terminal = case["projection"]["result"]
                    terminal["checks"][0]["reason"] = "timed-out"
                    terminal["lifetime"].update(commands=0, commandDispatched=False, stopObserved="timed-out")
                    terminal["outcome"] = "timed-out"
                result["unexecuted"].append({"case": "L5", "check": "git", "reason": reason})
                result["classification"] = "finite-incomplete-with-expected-driver-loss"
                self.assertEqual(helper.validate_environment_result(result, context, digest), result)
                false_success = deepcopy(result)
                false_success["classification"] = "finite-complete-with-expected-driver-loss"
                self.assert_refused(lambda value: helper.validate_environment_result(value, context, digest), false_success)
                erased_hold = deepcopy(result)
                erased_hold["cases"][helper.ENVIRONMENT_NATIVE_CASES.index("L5")]["timing"]["heldMs"] = None
                self.assert_refused(lambda value: helper.validate_environment_result(value, context, digest), erased_hold)

    def test_progress_stays_conservative_and_original_shell_step_is_a_required_gate(self) -> None:
        context = native_context()
        for count in (0, 7, 19, 20):
            progress = progress_value(context, count)
            self.assertEqual(helper.validate_environment_progress(progress, context), progress)
        for key, bad in (("classification", "passed"), ("completedCases", ["L7"]), ("nextCase", "L7"),
                         ("stage", "/private/raw/path"), ("failureCode", "arbitrary-runtime-output")):
            progress = progress_value(context)
            progress[key] = bad
            self.assert_refused(lambda value: helper.validate_environment_progress(value, context), progress)
        outer = outer_value(context)
        self.assertEqual(helper.validate_environment_outer(outer, context, step_outcome="success", success=True), outer)
        self.assert_refused(lambda value: helper.validate_environment_outer(value, context, step_outcome="failure", success=True), outer)
        self.assert_refused(lambda value: helper.validate_environment_outer(value, context, step_outcome="success", success=True), outer_value(context, 101))
        failure = outer_value(context, 101)
        self.assertEqual(helper.validate_environment_outer(failure, context, step_outcome="failure", success=False), failure)

    def test_failure_retention_only_reads_data_and_does_not_publish_raw_output(self) -> None:
        context, compile_receipt, invocation = compile_invocation()
        progress = progress_value(context, 19)
        progress.update(stage="negative-tail", failureCode="original-physical-finality")
        by_name = {"acquire-started.json": helper.environment_phase_claim(context, "acquire"),
            "compile-started.json": helper.environment_phase_claim(context, "compile"),
            "acquire-checks.json": helper.environment_phase_value(context, "acquire"), "compile-checks.json": compile_receipt,
            "environment-native-progress.json": progress, "environment-native-outer.json": outer_value(context, 101)}
        writes = {}
        def read_data(path, _limit):
            return deepcopy(by_name[path.name])
        def write_data(path, value):
            writes[path.name] = deepcopy(value)
        with patch.dict(helper.os.environ, {"MRK_ENVIRONMENT_NATIVE_STEP_OUTCOME": "failure"}, clear=True), \
                patch.object(helper.os.path, "lexists", return_value=False), \
                patch.object(helper, "read_bounded_json", side_effect=read_data), \
                patch.object(helper, "write_json", side_effect=write_data), \
                patch.object(helper, "environment_original_invocation", return_value=(invocation, "f" * 64)) as bound, \
                patch.object(helper, "source_unchanged", side_effect=AssertionError("source probe")), \
                patch.object(helper, "environment_inputs_unchanged", side_effect=AssertionError("runtime probe")), \
                patch.object(helper, "tools", side_effect=AssertionError("compiler probe")), \
                patch.object(helper.shutil, "rmtree", side_effect=AssertionError("cleanup")):
            with self.assertRaises(helper.CheckFailure):
                helper.retain_environment_native(context)
        bound.assert_called_once_with(context, inspect_artifact=False)
        public = writes["environment-native-public.json"]
        self.assertEqual(public["classification"], "native-not-verified")
        self.assertEqual(public["physicalOriginals"], "unverified")
        self.assertEqual(public["progress"]["nextCase"], "L7")
        self.assertEqual(public["progress"]["failureCode"], "original-physical-finality")
        self.assertFalse(public["retention"]["deleted"])
        self.assertIsNone(public["native"])
        for private in (context["root"], context["source"], context["python"]):
            self.assertNotIn(private.encode(), helper.canonical_json(public))

    def test_public_result_strips_help_text_without_rewriting_source_observations(self) -> None:
        _, result, _ = native_result()
        marker = "private-free-text-marker"
        check = result["cases"][5]["projection"]["result"]["checks"][0]
        check["help"] = marker
        public = helper.environment_sanitized_result(result)
        self.assertNotIn(marker.encode(), helper.canonical_json(public))
        self.assertEqual(check["help"], marker)
        self.assertEqual(public["cases"][5]["projection"]["result"]["checks"][0]["version"], check["version"])

    def test_selection_diagnostic_is_closed_optional_original_negative_data(self) -> None:
        projection = projection_value("macos", "R1")
        result, selected = projection["result"], projection["result"]["checks"][0]
        selected["reason"] = "selection-unrecognized"
        for check in result["checks"][1:]:
            check.update(state="not-run", reason="unselected-installation", version=None, build=None, returnCode=None, assessment="not-assessed")
        result["commandsAttempted"] = result["lifetime"]["commands"] = 1
        self.assertEqual(helper.validate_environment_projection(projection, "macos"), projection)
        for detail in (None, {"stage": "application", "reason": "directory-owner"},
                       {"stage": "alias", "reason": "target-encoding"}):
            selected["selectionDiagnostic"] = detail
            self.assertEqual(helper.validate_environment_projection(projection, "macos"), projection)
            public = helper.environment_sanitized_result({"cases": [{"projection": projection}]})
            self.assertEqual(public["cases"][0]["projection"]["result"]["checks"][0]["selectionDiagnostic"], detail)
            self.assertNotIn("help", public["cases"][0]["projection"]["result"]["checks"][0])
        detail = {"stage": "application", "reason": "directory-owner"}
        for bad in ({}, {"stage": "alias", "reason": "directory-owner"},
                    {"stage": "application", "reason": "target-encoding"},
                    {"stage": "PRIVATE_PATH", "reason": "directory-owner"}, {**detail, "path": "PRIVATE_PATH"}):
            selected["selectionDiagnostic"] = bad
            self.assert_refused(lambda value: helper.validate_environment_projection(value, "macos"), projection)
        selected["selectionDiagnostic"] = detail
        for key in ("id", "state", "reason", "version", "build", "returnCode", "baseline", "assessment", "help"):
            bad = deepcopy(projection)
            del bad["result"]["checks"][0][key]
            self.assert_refused(lambda value: helper.validate_environment_projection(value, "macos"), bad)
        for key, value in (("reason", "observed"), ("returnCode", 1)):
            bad = deepcopy(projection)
            bad["result"]["checks"][0][key] = value
            self.assert_refused(lambda value: helper.validate_environment_projection(value, "macos"), bad)
        result["checks"][1]["selectionDiagnostic"] = None
        self.assertEqual(helper.validate_environment_projection(projection, "macos"), projection)
        result["checks"][1]["selectionDiagnostic"] = detail
        self.assert_refused(lambda value: helper.validate_environment_projection(value, "macos"), projection)

    def test_source_routes_native_through_one_exec_with_no_cargo_or_cleanup_after_it(self) -> None:
        tree = ast.parse(HELPER.read_text(encoding="utf-8"))
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        phase = functions["phase_environment_native"]
        native = next(node for node in ast.walk(phase) if isinstance(node, ast.If)
                      and ast.unparse(node.test) == "name == 'environment-native'")
        calls = [ast.unparse(node.func) for statement in native.body for node in ast.walk(statement) if isinstance(node, ast.Call)]
        self.assertEqual(calls.count("os.execve"), 1)
        for forbidden in ("subprocess.run", "subprocess.Popen", "run", "tools", "shutil.rmtree"):
            self.assertNotIn(forbidden, calls)
        self.assertIn("environment_original_outer_outputs", calls)
        self.assertLess(calls.index("environment_original_outer_outputs"), calls.index("os.execve"))
        gate = ast.unparse(functions["environment_original_outer_outputs"])
        self.assertIn("RLIMIT_FSIZE", gate)
        self.assertIn("os.fstat", gate)

    def test_workflow_is_two_fixed_profiles_one_compile_and_preowned_original_wait(self) -> None:
        workflow = (SOURCE / helper.ENVIRONMENT_NATIVE_WORKFLOW).read_text(encoding="utf-8")
        mac = '{"include":[{"platform":"macos","runner":"macos-26"}]}'
        both = '{"include":[{"platform":"linux","runner":"ubuntu-24.04"},{"platform":"macos","runner":"macos-26"}]}'
        self.assertIn("matrix: ${{ fromJSON(github.ref == '" + helper.ENVIRONMENT_NATIVE_MACOS_REF + "' && '" + mac + "' || '" + both + "') }}", workflow)
        gate = 'case "$GITHUB_REF:$MRK_DESKTOP_PLATFORM" in'
        pairs = helper.ENVIRONMENT_NATIVE_REF + ":linux|" + helper.ENVIRONMENT_NATIVE_REF + ":macos|" + helper.ENVIRONMENT_NATIVE_MACOS_REF + ":macos) ;;"
        self.assertIn(pairs, workflow)
        self.assertLess(workflow.index(gate), workflow.index("uses: actions/checkout@"))
        self.assertIn("*) exit 1 ;;", workflow[workflow.index(gate):workflow.index("uses: actions/checkout@")])
        fixture = (SOURCE / "desktop/src-tauri/src/environment_diagnostics_hosted_tests.rs").read_text(encoding="utf-8")
        self.assertIn('("' + helper.ENVIRONMENT_NATIVE_REF + '", "linux" | "macos")', fixture)
        self.assertIn('("' + helper.ENVIRONMENT_NATIVE_MACOS_REF + '", "macos")', fixture)
        self.assertIn("contents: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        for phase in helper.ENVIRONMENT_NATIVE_PHASES:
            self.assertEqual(workflow.count("desktop/tools/ci_foundation.py " + phase), 1)
        for unwanted in ("setup-node@", "apt-get", "cargo test", "continue-on-error", "contents: write"):
            self.assertNotIn(unwanted, workflow)
        setup_marker = "      - name: Select installed root-owned CLT for macOS lifecycle verification\n"
        prepare_marker = "      - name: Prepare exact bounded source and ZIP bindings\n"
        setup = workflow.split(setup_marker, 1)[1].split(prepare_marker, 1)[0]
        self.assertLess(workflow.index("uses: actions/setup-python@"), workflow.index(setup_marker))
        self.assertLess(workflow.index(setup_marker), workflow.index(prepare_marker))
        self.assertIn("if: matrix.platform == 'macos'", setup)
        self.assertIn("timeout-minutes: 1", setup)
        self.assertIn('"$MRK_PYTHON" -I -S -B desktop/tools/environment_macos_clt.py', setup)
        self.assertEqual(setup.count("/usr/bin/sudo -n /usr/bin/xcode-select --switch /Library/Developer/CommandLineTools </dev/null"), 1)
        self.assertEqual(setup.count("/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C LC_ALL=C TZ=UTC"), 2)
        self.assertIn("/usr/bin/xcode-select -p </dev/null && printf '.'", setup)
        self.assertIn('[[ "$selected" == $\'/Library/Developer/CommandLineTools\\n.\' ]]', setup)
        self.assertNotIn("sudo", workflow.replace(setup, ""))
        self.assertEqual(setup.count("sudo"), 1)
        for forbidden in ("sudo -n /bin", "--install", "chown ", "chmod ", "--reset", "continue-on-error"):
            self.assertNotIn(forbidden, setup)
        launch = workflow.index("desktop/tools/ci_foundation.py environment-native")
        self.assertLess(workflow.index('exec 3>"$MRK_DESKTOP_CI_ROOT/environment-native-outer.json"'), launch)
        self.assertLess(workflow.index('exec 4>"$MRK_DESKTOP_CI_ROOT/environment-native.stdout"'), launch)
        self.assertLess(workflow.index('exec 5>"$MRK_DESKTOP_CI_ROOT/environment-native.stderr"'), launch)
        self.assertIn("</dev/null 1>&4 2>&5 3>&- 4>&- 5>&-", workflow)
        self.assertIn("result=$?", workflow)
        self.assertIn("exec 4>&- 5>&- || exit 125", workflow)
        self.assertIn("exec 3>&- || exit 125", workflow)
        self.assertIn('exit "$result"', workflow)
        self.assertIn("MRK_ENVIRONMENT_NATIVE_STEP_OUTCOME: ${{ steps.native.outcome }}", workflow)
        self.assertIn("path: ${{ steps.prepare.outputs.root }}/environment-native-public.json", workflow)
        self.assertIn("if: always() && steps.prepare.outcome == 'success' && steps.native.outcome != 'skipped'", workflow)


if __name__ == "__main__":
    unittest.main()
