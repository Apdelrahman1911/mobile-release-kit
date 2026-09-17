"""Fixed desktop compiler/native boundary checks on disposable hosted runners only.

Not the release-kit verification controller, a release workflow, an installer,
or a general command runner. Never invoke this on a shared development machine.
Compiler completion is not proof of desktop/native-child finality; the ignored
Rust test owns and reports those original-child observations separately.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import TextIO
import zipfile

RUST = "1.98.0"
PYTHON = "3.14.7"
NODE = "v24.20.0"
BOUNDARY_SCOPE = "passive-v1"
COMPILE_SCOPE = "shell-compile-v1"
COMPILE_EVIDENCE_SCOPE = "desktop-shell-compile-only-v1"
COMPILE_WORKFLOW = ".github/workflows/desktop-session-compile.yml"
COMPILE_REF = "refs/heads/verify/desktop-session-compile"
COMPILE_PHASES = ("prepare", "acquire", "compile", "clean")
COMPILE_CHECKS = {
    "acquire": ("rust-toolchain-install", "rust-version-target", "locked-platform-metadata",
                "node-version", "npm-locked-no-scripts"),
    "compile": ("rust-version-target", "headless-test-compile-only", "node-version",
                "typescript-no-emit", "vite-assets", "tauri-debug-compile-only"),
}
EMPTY_NATIVE_DIRECTORIES = (
    "native", "config-owner", "config-driver-loss", "config-watchdog-loss", "config-stop",
    "config-terminal-deadline", "config-startup-stop", "config-transaction-eof",
)
COMPILER_DIRECTORIES = ("home", "cargo", "rustup", "tmp", "target", "appdata", "localappdata", "npm-cache")
COMPILER_PRIVATE_FILES = ("context.json", "core.zip", "metadata.json", "npmrc-user", "npmrc-global", "gitconfig-empty")
COMPILE_PUBLIC_FILES = ("public-bindings.json", "acquire-checks.json", "compile-checks.json")
NATIVE_TEST = "supervisor::hosted_tests::passive_hosted_contract"
CONFIG_OWNER_TEST = "edit_owner::hosted_tests::hosted_config_edit_owner_original_resources"
CONFIG_DRIVER_LOSS_TEST = "edit_owner::hosted_tests::hosted_config_driver_loss_original_resources"
CONFIG_WATCHDOG_LOSS_TEST = "edit_owner::hosted_tests::hosted_config_watchdog_loss_original_resources"
CONFIG_STOP_TEST = "edit_owner::hosted_tests::hosted_config_stop_original_resources"
CONFIG_TERMINAL_DEADLINE_TEST = "edit_owner::hosted_tests::hosted_config_terminal_deadline_original_resources"
CONFIG_STARTUP_STOP_TEST = "edit_owner::hosted_tests::hosted_config_startup_stop_original_resources"
CONFIG_TRANSACTION_EOF_TEST = "edit_owner::hosted_tests::hosted_config_transaction_eof_original_resources"
TARGETS = {
    "linux": "x86_64-unknown-linux-gnu",
    "macos": "aarch64-apple-darwin",
    "windows": "x86_64-pc-windows-msvc",
}
NATIVE_CASES = (
    "core-capabilities", "core-catalog", "core-zip-catalog", "core-valid-draft",
    "core-invalid-draft", "core-service-error", "core-snapshot", "malformed",
    "truncated", "extra_frames", "wrong_id", "nonzero_exit", "pipe_pressure",
    "stdout_limit", "stderr_limit", "delay_exit", "busy-abandon", "operation-timeout",
    "shutdown-active", "controlled-startup", "controlled-io-join",
    "controlled-management-returns", "controlled-management-late",
)
CONFIG_PARTITIONS = ("ordinary", "committed-fsync", "committed-close")
CONFIG_CASES = {
    "ordinary": (
        "create", "save", "no-op", "ignore-append", "ignore-conflict", "invalid-existing",
        "single-link-admission", "stale-config-bytes", "stale-config-inode", "stale-ignore-after-prepare",
        "stale-release", "absent-release-appeared", "stale-root", "init-0", "init-1", "init-2",
        "build-pending", "build-terminal", "build-stage", "init-alias", "malformed-private-mode",
        "contention-init", "contention-build", "idle-review-unlocked", "precommit-publication-injection",
        "legacy-public-commit", "legacy-public-rollback",
    ),
    "committed-fsync": ("committed-fsync-injection",),
    "committed-close": ("committed-close-return-injection",),
}
CONFIG_INJECTIONS = {
    "ordinary": "precommit-publication",
    "committed-fsync": "postdecision-pre-fsync",
    "committed-close": "postcommit-cancellation-and-positive-scope-close-return-loss",
}
CONFIG_OWNER_SOURCES = {
    "fixture": "desktop/src-tauri/src/edit_hosted_tests.rs",
    "owner": "desktop/src-tauri/src/edit_owner.rs",
    "editProtocol": "desktop/src-tauri/src/edit_protocol.rs",
    "runtime": "desktop/src-tauri/src/runtime.rs",
    "protocol": "desktop/src-tauri/src/protocol.rs",
    "errors": "desktop/src-tauri/src/error.rs",
    "library": "desktop/src-tauri/src/lib.rs",
    "build": "desktop/src-tauri/build.rs",
    "cargoManifest": "desktop/src-tauri/Cargo.toml",
    "cargoLock": "desktop/src-tauri/Cargo.lock",
    "bootstrap": "desktop/config_edit_bootstrap.py",
    "passiveBootstrap": "desktop/engine_bootstrap.py",
    "corePackage": "src/mobile_release/__init__.py",
    "engine": "src/mobile_release/_desktop_edit_engine.py",
    "control": "src/mobile_release/_desktop_edit_control.py",
    "coreProtocol": "src/mobile_release/_desktop_edit_protocol.py",
    "configEdit": "src/mobile_release/config_edit.py",
    "configPayloads": "src/mobile_release/config_payloads.py",
    "config": "src/mobile_release/config.py",
    "transaction": "src/mobile_release/init_transaction.py",
    "rootCustody": "src/mobile_release/init_workspace_custody.py",
    "cancellation": "src/mobile_release/cancellation.py",
    "buildInputs": "src/mobile_release/build_inputs.py",
    "coreErrors": "src/mobile_release/errors.py",
    "preview": "src/mobile_release/api/_preview.py",
    "nativeFixture": "tests/native_desktop_config.py",
}
CONFIG_OWNER_NOT_VERIFIED = (
    "production-runtime-custody", "production-save-enablement", "native-gui", "window-reload-crash",
    "parent-death", "native-stuck-wait-close", "windows-filesystem", "stores", "mobile-builds", "installers",
)
CONFIG_TRANSACTION_EOF_SOURCES = {
    **CONFIG_OWNER_SOURCES,
    "transactionEofShim": "tests/native_desktop_config_eof.py",
}
CONFIG_OWNER_FINALITY = (
    "originalWait", "stdoutEof", "stderrEof", "stdinClosed", "stdoutClosed", "stderrClosed",
    "startupJoined", "ioJoined", "driverJoined", "watchdogJoined", "managerJoined",
)
TOOL_CHECKS = frozenset({
    "source-head", "source-tree", "source-clean", "rust-toolchain-install",
    "cargo-selection", "rustc-selection", "rust-version-target", "locked-platform-metadata",
    "node-version", "npm-locked-no-scripts", "headless-test-compile-only",
    "typescript-no-emit", "vite-assets", "tauri-debug-compile-only", "passive-native-contract",
    "config-core-ordinary", "config-core-committed-fsync", "config-core-committed-close",
    "config-owner-native-contract",
    "config-driver-loss-native-contract", "config-watchdog-loss-native-contract",
    "config-stop-native-contract", "config-terminal-deadline-native-contract", "config-startup-stop-native-contract",
    "config-transaction-eof-native-contract",
})


class CheckFailure(ValueError):
    """Fixed, non-secret diagnostic for an explicit check condition."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def admit_phase(scope: str, phase: str) -> None:
    """Closed scope selection, before context, tools, or native dispatch."""
    require(scope in {BOUNDARY_SCOPE, COMPILE_SCOPE}, "Unknown desktop verification scope")
    if scope == COMPILE_SCOPE:
        require(phase in COMPILE_PHASES, "Compiler-only scope cannot execute a native phase")


def compile_workflow_binding(environment: dict[str, str]) -> dict[str, str]:
    """Pure binding to the actual fixed verification workflow, not a caller path."""
    sha, repository = environment.get("GITHUB_SHA", ""), environment.get("GITHUB_REPOSITORY", "")
    run_id, attempt = environment.get("GITHUB_RUN_ID", ""), environment.get("GITHUB_RUN_ATTEMPT", "")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None
            and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None,
            "Compiler workflow source identity differs")
    require(all(re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None for value in (run_id, attempt)),
            "Compiler workflow run identity differs")
    require(environment.get("GITHUB_REF") == COMPILE_REF
            and environment.get("GITHUB_WORKFLOW_SHA") == sha
            and environment.get("GITHUB_WORKFLOW_REF") == f"{repository}/{COMPILE_WORKFLOW}@{COMPILE_REF}",
            "Compiler workflow/ref binding differs")
    event = environment.get("GITHUB_EVENT_NAME")
    require(event == "push" or event == "workflow_dispatch" and environment.get("MRK_EXPECTED_SHA") == sha,
            "Compiler workflow event or exact dispatch source differs")
    return {"workflowPath": COMPILE_WORKFLOW, "workflowSha": sha,
            "workflowRef": environment["GITHUB_WORKFLOW_REF"], "sourceSha": sha,
            "runId": run_id, "attempt": attempt}


def validate_compile_receipt(value: object, context: dict, phase: str) -> dict:
    """A compile receipt licenses only compiler-output cleanup, not native finality."""
    require(phase in COMPILE_CHECKS and context.get("executionScope") == COMPILE_SCOPE,
            "Compiler receipt scope differs")
    require(type(value) is dict, "Missing compiler phase receipt")
    binding_names = ("sourceSha", "platform", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt")
    expected = {
        "schemaVersion": 1, "scope": COMPILE_EVIDENCE_SCOPE, "phase": phase, "status": "passed",
        **{name: context[name] for name in binding_names},
        "rust": {"release": RUST, "target": TARGETS[context["platform"]]}, "node": NODE,
        "checks": [{"check": name, "exitCode": 0} for name in COMPILE_CHECKS[phase]],
    }
    require(type(value.get("schemaVersion")) is int and value == expected
            and all(type(row.get("exitCode")) is int for row in value.get("checks", [])),
            "Compiler phase receipt is incomplete or its original source/checks differ")
    return value


def parse_compile_receipt(raw: bytes) -> object:
    require(type(raw) is bytes and 0 < len(raw) <= 16384, "Compiler phase receipt exceeds its bound")
    def pairs(items: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate compiler receipt field")
            result[key] = value
        return result
    def nonfinite(_: str) -> None:
        raise CheckFailure("Nonfinite compiler receipt value")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=nonfinite)
    except (ValueError, UnicodeError, RecursionError):
        raise CheckFailure("Malformed compiler phase receipt") from None


def validate_compile_inventory(names: set[str], nonempty_native: set[str]) -> None:
    expected = set(COMPILER_DIRECTORIES + EMPTY_NATIVE_DIRECTORIES + COMPILER_PRIVATE_FILES + COMPILE_PUBLIC_FILES)
    require(names == expected and not nonempty_native,
            "Compiler-only task contains missing, unexpected, or native outputs; retain it")


def ordinary(path: Path) -> None:
    details = path.lstat()
    require(stat.S_ISREG(details.st_mode) and details.st_nlink == 1
            and not getattr(details, "st_file_attributes", 0) & 0x400,
            "Expected an ordinary, single-link file")


def hash_file(path: Path) -> str:
    ordinary(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")


def run(argv: list[str], *, check: str, cwd: Path, env: dict[str, str], timeout: int,
        capture: bool = False, output: TextIO | None = None) -> str:
    # Only fixed commands below reach this internal helper. No shell, inherited
    # credentials, renderer input, project hook or arbitrary command selection.
    require(check in TOOL_CHECKS, "Unknown fixed compiler check")
    require(not (capture and output is not None), "Conflicting compiler output destinations")
    print(f"Fixed check: {check}", flush=True)
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, check=True, timeout=timeout,
                                text=True, stdout=subprocess.PIPE if capture else output)
    except subprocess.CalledProcessError as error:
        # Do not interpolate exception text: it includes argv and may contain
        # local paths or captured output. These labels come only from fixed code.
        raise CheckFailure(f"Fixed check {check} exited {error.returncode}") from None
    except subprocess.TimeoutExpired:
        raise CheckFailure(f"Fixed check {check} exceeded its deadline") from None
    except OSError:
        raise CheckFailure(f"Fixed check {check} could not start") from None
    if capture:
        require(len(result.stdout.encode("utf-8")) <= 1024 * 1024, "Tool metadata exceeded its bound")
        return result.stdout.strip()
    return ""


def admitted_host() -> str:
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("MRK_DESKTOP_HOSTED_CHECKS") in {BOUNDARY_SCOPE, COMPILE_SCOPE},
            "This fixed check requires an explicitly admitted disposable hosted job")
    platform = os.environ.get("MRK_DESKTOP_PLATFORM", "")
    require(platform in TARGETS and platform == {
        "linux": "linux", "darwin": "macos", "win32": "windows",
    }.get(sys.platform), "Unexpected host platform")
    require(sys.version.split()[0] == PYTHON, "Unexpected selected Python version")
    selected = Path(os.environ["MRK_PYTHON"]).resolve(strict=True)
    require(selected == Path(sys.executable).resolve(strict=True), "Python setup output differs")
    return platform


def clean_environment(root: Path) -> dict[str, str]:
    # The ordinary compiler PATH is supplied by the trusted hosted image/setup
    # Actions. It is not a production-runtime admission or application PATH.
    environment = {"PATH": os.environ["PATH"], "HOME": str(root / "home"),
                   "CARGO_HOME": str(root / "cargo"), "RUSTUP_HOME": str(root / "rustup"),
                   "TMPDIR": str(root / "tmp"), "TMP": str(root / "tmp"), "TEMP": str(root / "tmp"),
                   "LC_ALL": "C", "LANG": "C", "CARGO_INCREMENTAL": "0",
                   "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": str(root / "gitconfig-empty"),
                   "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
                   "NODE_DISABLE_COMPILE_CACHE": "1", "ESBUILD_WORKER_THREADS": "0", "GOMAXPROCS": "2"}
    if sys.platform == "win32":
        for name in ("SystemRoot", "SystemDrive", "COMSPEC", "PATHEXT", "ProgramFiles",
                     "ProgramFiles(x86)", "ProgramW6432", "WINDIR", "INCLUDE", "LIB", "LIBPATH",
                     "VCToolsInstallDir", "VCINSTALLDIR", "VSINSTALLDIR", "WindowsSdkDir",
                     "WindowsSDKVersion", "UniversalCRTSdkDir", "UCRTVersion"):
            if name in os.environ:
                environment[name] = os.environ[name]
        environment.update(USERPROFILE=str(root / "home"), APPDATA=str(root / "appdata"),
                           LOCALAPPDATA=str(root / "localappdata"))
    return environment


def source_unchanged(context: dict) -> None:
    source, root = Path(context["source"]), Path(context["root"])
    git = context["git"]
    environment = clean_environment(root)
    require(run([git, "rev-parse", "HEAD"], check="source-head", cwd=source, env=environment, timeout=15, capture=True)
            == context["sourceSha"], "Checkout commit changed")
    run([git, "diff", "--no-ext-diff", "--no-textconv", "--exit-code", "--quiet", "HEAD", "--"],
        check="source-clean", cwd=source, env=environment, timeout=15)


def no_cargo_configuration(directories: tuple[Path, ...]) -> None:
    for directory in directories:
        for name in ("config", "config.toml"):
            path = directory / ".cargo" / name
            require(not path.exists() and not path.is_symlink(), "Ambient Cargo configuration is not admitted")


def validate_native_receipt(receipt: object, *, source_sha: str, platform: str, core_zip_hash: str) -> dict:
    require(platform in TARGETS and isinstance(receipt, dict), "Unexpected native receipt")
    require(type(receipt.get("schemaVersion")) is int and receipt.get("schemaVersion") == 1
            and receipt.get("scope") == "passive-hosted-v2"
            and receipt.get("status") == "passed" and receipt.get("allOwnersSettled") is True,
            "Native ownership is not confirmed settled; preserve outputs")
    bindings = receipt.get("bindings", {})
    require(isinstance(bindings, dict) and bindings.get("sourceSha") == source_sha
            and bindings.get("target") == TARGETS[platform] and bindings.get("coreZipSha256") == core_zip_hash,
            "Native receipt source/target differs")
    cases = receipt.get("cases", [])
    require(isinstance(cases, list) and all(isinstance(case, dict) for case in cases)
            and tuple(case.get("case") for case in cases) == NATIVE_CASES
            and all(case.get("passed") is True for case in cases), "Fixed native batch was not fully verified")
    # Keep the original 21 cases' acceptance predicates. Only the two new v2
    # records add this closed management-return contract; notes alone cannot
    # replace the original native/IO/management observations and retirement.
    case_fields = {"case", "passed", "failureCode", "elapsedMs", "evidenceKind", "results", "notes", "owners",
                   "registeredOwners", "disabled"}
    native_flags = ("inspection_joined", "acquisition_joined", "spawned", "waited", "exit_success",
                    "writer_joined", "writer_complete", "stdout_eof", "stderr_eof", "stdout_joined", "stderr_joined",
                    "driver_joined", "watchdog_joined")
    checkpoint_notes = (
        {"nativeSettledBeforeManagementReturns", "driverReturnHeldBeforeReply", "watchdogReturnHeldBeforeReply"},
        {"nativeSettledBeforeWatchdogReturn", "originalCleanupEndpointUnchanged", "retainedWhileUnknown",
         "newQueryRefused", "lateJoinPreservedFailure"},
    )
    for case, late, notes in zip(cases[-2:], (False, True), checkpoint_notes, strict=True):
        require(set(case) == case_fields and case["failureCode"] is None
                and case["evidenceKind"] == "scheduling-control-not-os-fault"
                and case["disabled"] is late and type(case["registeredOwners"]) is int and case["registeredOwners"] == 0,
                "Native management case or retirement differs")
        require(type(case["elapsedMs"]) is int and case["elapsedMs"] >= (2000 if late else 0),
                "Native management cleanup allowance differs")
        expected_result = {"return": "error", "code": "cleanup_unknown"} if late else {"return": "ok"}
        require(case["results"] == [expected_result], "Native management result differs")
        require(isinstance(case["notes"], dict) and set(case["notes"]) == notes
                and all(case["notes"][field] is True for field in notes), "Native management checkpoint facts differ")
        owners = case["owners"]
        require(isinstance(owners, list) and len(owners) == 1 and isinstance(owners[0], dict),
                "Native management original owner inventory differs")
        owner = owners[0]
        require(set(owner) == {"id", "terminal", "unknownLatched", "permitRetained", "native"}
                and owner["id"] == "query-1" and owner["terminal"] is True
                and owner["permitRetained"] is False and owner["unknownLatched"] is late,
                "Native management original owner finality differs")
        native = owner["native"]
        require(isinstance(native, dict) and set(native) == {*native_flags, "stdout_bytes", "stderr_bytes"}
                and all(native[field] is True for field in native_flags), "Native management original returns are incomplete")
        require(type(native["stdout_bytes"]) is int and 0 < native["stdout_bytes"] <= 4 * 1024 * 1024
                and type(native["stderr_bytes"]) is int and 0 <= native["stderr_bytes"] <= 64 * 1024,
                "Native management output accounting differs")
    return receipt


def native_receipt(context: dict) -> dict:
    path = Path(context["root"]) / "native/receipt.json"
    ordinary(path)
    size = path.stat().st_size
    require(0 < size <= 64 * 1024, "Native receipt size differs")
    with path.open("rb") as stream:
        data = stream.read(size + 1)
    require(len(data) == size, "Native receipt changed")
    return validate_native_receipt(json.loads(data), source_sha=context["sourceSha"], platform=context["platform"],
        core_zip_hash=hash_file(Path(context["root"]) / "core.zip"))


def validate_config_receipt(receipt: object, partition: str) -> dict:
    require(partition in CONFIG_PARTITIONS and isinstance(receipt, dict), "Unexpected configuration receipt")
    require(set(receipt) == {"suite", "partition", "status", "reason", "completed", "failedAt", "retained",
                             "uncertaintyLatched", "injection"}, "Configuration receipt fields differ")
    require(receipt["suite"] == "desktop-config-native" and receipt["partition"] == partition
            and receipt["status"] == "passed" and receipt["reason"] == "none" and receipt["failedAt"] is None,
            "Configuration fixture did not pass; preserve outputs")
    require(isinstance(receipt["completed"], list) and tuple(receipt["completed"]) == CONFIG_CASES[partition]
            and receipt["injection"] == CONFIG_INJECTIONS[partition], "Configuration case inventory differs")
    require(receipt["retained"] is (partition != "ordinary")
            and receipt["uncertaintyLatched"] is (partition == "committed-close"),
            "Configuration fixture retention/uncertainty differs")
    return receipt


def config_receipt(context: dict, partition: str) -> dict:
    require(partition in CONFIG_PARTITIONS, "Unknown configuration partition")
    path = Path(context["root"]) / f"config-{partition}.json"
    ordinary(path)
    require(0 < path.stat().st_size <= 16 * 1024, "Configuration receipt exceeded its bound")
    with path.open("rb") as stream:
        data = stream.read(16 * 1024 + 1)
    require(len(data) <= 16 * 1024, "Configuration receipt changed")
    return validate_config_receipt(json.loads(data), partition)


def validate_config_owner_bindings(bindings: object, *, source_sha: str, platform: str,
                                    source_hashes: dict[str, str], python_hash: str) -> None:
    require(platform in {"linux", "macos"} and isinstance(bindings, dict)
            and set(bindings) == {"sourceSha", "host", "target", "runtimeMode", "pythonSha256", "sourceHashes", "payloadHashes"}
            and bindings["sourceSha"] == source_sha and bindings["host"] == platform
            and bindings["target"] == TARGETS[platform] and bindings["runtimeMode"] == "trusted-development-only"
            and bindings["pythonSha256"] == python_hash and bindings["sourceHashes"] == source_hashes,
            "Configuration owner source/runtime bindings differ")
    payloads = bindings["payloadHashes"]
    require(isinstance(payloads, dict) and set(payloads) == {"draft", "createConfig", "createIgnore", "noOpConfig", "noOpIgnore", "unrelated"}
            and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in payloads.values()),
            "Configuration owner payload bindings differ")


def validate_config_owner_receipt(receipt: object, *, source_sha: str, platform: str,
                                  source_hashes: dict[str, str], python_hash: str) -> dict:
    require(platform in {"linux", "macos"} and isinstance(receipt, dict), "Unexpected configuration owner receipt")
    require(set(receipt) == {"schemaVersion", "scope", "status", "allOwnersSettled", "failureCode", "bindings", "cases", "notVerified"}
            and type(receipt["schemaVersion"]) is int and receipt["schemaVersion"] == 1
            and receipt["scope"] == "configuration-owner-hosted-v1" and receipt["status"] == "passed"
            and receipt["allOwnersSettled"] is True and receipt["failureCode"] is None,
            "Configuration original ownership is unconfirmed; preserve outputs")
    require(receipt["notVerified"] == list(CONFIG_OWNER_NOT_VERIFIED), "Configuration owner scope differs")
    validate_config_owner_bindings(receipt["bindings"], source_sha=source_sha, platform=platform,
                                    source_hashes=source_hashes, python_hash=python_hash)
    cases = receipt["cases"]
    require(isinstance(cases, list) and len(cases) == 3, "Configuration owner case inventory differs")
    fields = {"name", "outcome", "nativeReason", "nativeFinality", "requestFrames", "responseFrames", "stdoutBytes", "stderrBytes", "forceAttempted", *CONFIG_OWNER_FINALITY}
    for case, name, effect, journal, native_reason, requests, responses in zip(
        cases, ("create", "no-op", "discard-editing"), ("committed", "unchanged", "not_started"),
        ("clean", "not_created", "not_created"), ("none", "none", "discarded"), (3, 3, 1), (3, 3, 2), strict=True,
    ):
        require(isinstance(case, dict) and set(case) == fields and case["name"] == name
                and case["nativeReason"] == native_reason and case["nativeFinality"] == "settled"
                and all(case[field] is True for field in CONFIG_OWNER_FINALITY)
                and case["forceAttempted"] is False, "Configuration original resource receipt differs")
        require(all(type(case[field]) is int for field in ("requestFrames", "responseFrames", "stdoutBytes", "stderrBytes"))
                and case["requestFrames"] == requests and case["responseFrames"] == responses
                and 0 < case["stdoutBytes"] <= 12 * 1024 * 1024 and case["stderrBytes"] == 0,
                "Configuration frame/output accounting differs")
        outcome = case["outcome"]
        require(isinstance(outcome, dict) and set(outcome) == {"effect", "journal", "resources", "reason"}
                and outcome["effect"] == effect and outcome["journal"] == journal and outcome["resources"] == "settled"
                and outcome["reason"] in (("none", "cancelled") if name == "discard-editing" else ("none",)),
                "Configuration owner effect/finality differs")
    return receipt


def validate_config_loss_receipt(receipt: object, kind: str, *, source_sha: str, platform: str,
                                 source_hashes: dict[str, str], python_hash: str) -> dict:
    require(kind in ("driver-loss", "watchdog-loss") and isinstance(receipt, dict), "Unexpected management-loss receipt")
    require(set(receipt) == {"schemaVersion", "scope", "status", "failureCode", "bindings", "case", "notVerified"}
            and type(receipt["schemaVersion"]) is int and receipt["schemaVersion"] == 1
            and receipt["scope"] == "configuration-owner-management-loss-hosted-v1"
            and receipt["status"] == "passed" and receipt["failureCode"] is None
            and receipt["notVerified"] == list(CONFIG_OWNER_NOT_VERIFIED), "Management-loss fixture did not pass; preserve outputs")
    validate_config_owner_bindings(receipt["bindings"], source_sha=source_sha, platform=platform,
                                    source_hashes=source_hashes, python_hash=python_hash)
    case = receipt["case"]
    fields = {"name", "nativePhase", "nativeFinality", "registryDisabled", "editPermitClosed", "nativeCanExit",
              "originalResourcesSettled", "failedTask", "failedJoinKind", "failedTaskHandleRetained",
              "requestFrames", "responseFrames", "stdoutBytes", "stderrBytes", "forceAttempted", *CONFIG_OWNER_FINALITY}
    require(isinstance(case, dict) and set(case) == fields and case["name"] == kind
            and case["nativePhase"] == "unknown" and case["nativeFinality"] == "unknown"
            and case["registryDisabled"] is True and case["editPermitClosed"] is True and case["nativeCanExit"] is False
            and case["originalResourcesSettled"] is True and case["failedTask"] == kind.removesuffix("-loss")
            and case["failedJoinKind"] == "panic" and case["failedTaskHandleRetained"] is True
            and case["forceAttempted"] is False, "Management uncertainty or original native settlement differs")
    # Only the injected management task lacks a normal return. Its actual panic
    # JoinError remains retained; every independent resource-bearing task joined.
    require(case["driverJoined"] is (kind != "driver-loss") and case["watchdogJoined"] is (kind != "watchdog-loss")
            and all(case[field] is True for field in CONFIG_OWNER_FINALITY if field not in {"driverJoined", "watchdogJoined"}),
            "Management-loss original task receipts differ")
    require(all(type(case[field]) is int for field in ("requestFrames", "responseFrames", "stdoutBytes", "stderrBytes"))
            and case["requestFrames"] == 1 and case["responseFrames"] == 2
            and 0 < case["stdoutBytes"] <= 12 * 1024 * 1024 and case["stderrBytes"] == 0,
            "Management-loss original frame accounting differs")
    return receipt


def validate_config_delta_receipt(receipt: object, kind: str, *, source_sha: str, platform: str,
                                  source_hashes: dict[str, str], python_hash: str) -> dict:
    require(kind in {"stop", "terminal-deadline", "startup-stop"} and isinstance(receipt, dict),
            "Unexpected configuration lifecycle receipt")
    stopping = kind == "stop"
    fields = {"schemaVersion", "scope", "status", "failureCode", "bindings", "notVerified"}
    fields.update({"allOwnersSettled", "cases"} if stopping else {"case"})
    require(set(receipt) == fields and type(receipt["schemaVersion"]) is int and receipt["schemaVersion"] == 1
            and receipt["scope"] == ("configuration-owner-stop-hosted-v1" if stopping else
                                     "configuration-owner-clock-retention-hosted-v1")
            and receipt["status"] == "passed" and receipt["failureCode"] is None
            and receipt["notVerified"] == list(CONFIG_OWNER_NOT_VERIFIED),
            "Configuration lifecycle fixture did not pass its exact scope")
    validate_config_owner_bindings(receipt["bindings"], source_sha=source_sha, platform=platform,
                                    source_hashes=source_hashes, python_hash=python_hash)
    common = {"name", "evidenceKind", "nativePhase", "nativeFinality", "nativeReason", "applySubmitted",
              "outcome", "terminalSeq", "requestFrames", "responseFrames", "stdoutBytes", "stderrBytes",
              "forceAttempted", *CONFIG_OWNER_FINALITY}
    if stopping:
        require(receipt["allOwnersSettled"] is True and isinstance(receipt["cases"], list)
                and len(receipt["cases"]) == 2, "Configuration stop case inventory differs")
        for case, name, evidence, reason, applying, prefix in zip(
            receipt["cases"], ("discard-reviewing", "partial-apply-eof"),
            ("actual-config-child", "fixed-prefix-scheduling-control"), ("discarded", "cancelled"),
            (False, True), (0, 1), strict=True,
        ):
            require(isinstance(case, dict) and set(case) == common | {"preparedCorrelation", "prefixBytes", "applySuffixStarted"}
                    and case["name"] == name and case["evidenceKind"] == evidence
                    and case["nativePhase"] == "final" and case["nativeFinality"] == "settled"
                    and case["nativeReason"] == reason and case["applySubmitted"] is applying
                    and all(case[field] is True for field in CONFIG_OWNER_FINALITY)
                    and case["preparedCorrelation"] is True and case["applySuffixStarted"] is False
                    and case["forceAttempted"] is False, "Configuration stop original custody differs")
            require(all(type(case[field]) is int for field in
                        ("requestFrames", "responseFrames", "stdoutBytes", "stderrBytes", "prefixBytes", "terminalSeq"))
                    and case["requestFrames"] == 2 and case["responseFrames"] == 3
                    and 0 < case["stdoutBytes"] <= 12 * 1024 * 1024 and case["stderrBytes"] == 0
                    and case["terminalSeq"] == 1 and case["prefixBytes"] == prefix
                    and case["outcome"] == {"effect": "not_started", "journal": "not_created", "resources": "settled", "reason": "cancelled"},
                    "Configuration partial-input or prepared-EOF outcome differs")
    else:
        terminal = kind == "terminal-deadline"
        case = receipt["case"]
        additional = {"registryDisabled", "editPermitClosed", "editAvailability", "nativeCanExit",
                      "originalResourcesSettled", "lateSettled", "retainedBeforeRelease", "cleanupStartUnchanged",
                      "cleanupElapsedMs", "scheduledActiveDeadline", "inspectionJoined", "acquisitionNotAdmitted",
                      "pipeAcquisition", "controlEntered", "controlReleased", "shutdownObserved"}
        require(isinstance(case, dict) and set(case) == common | additional and case["name"] == kind
                and case["evidenceKind"] == "scheduling-control-not-os-fault"
                and case["nativePhase"] == "unknown" and case["nativeFinality"] == "unknown"
                and case["nativeReason"] == ("active_timeout" if terminal else "discarded")
                and case["applySubmitted"] is terminal and case["forceAttempted"] is False
                and case["editAvailability"] == ("shutdown" if terminal else "cleanup_unknown"),
                "Configuration clock control cannot claim normal owner success")
        require(all(case[field] is True for field in (
                    "registryDisabled", "editPermitClosed", "nativeCanExit", "originalResourcesSettled", "lateSettled",
                    "retainedBeforeRelease", "cleanupStartUnchanged", "inspectionJoined", "controlEntered", "controlReleased"))
                and case["scheduledActiveDeadline"] is terminal and case["shutdownObserved"] is terminal
                and case["acquisitionNotAdmitted"] is (not terminal)
                and case["pipeAcquisition"] == ("available" if terminal else "absent"),
                "Configuration retained-to-late-settlement facts differ")
        # The childless case proves positive inspection/STOP refusal/Absent and
        # original IO/management joins. No wait, close, EOF or acquisition join
        # is invented for endpoints that were never acquired.
        for field in CONFIG_OWNER_FINALITY:
            require(case[field] is (terminal or field in {"ioJoined", "driverJoined", "watchdogJoined", "managerJoined"}),
                    "Configuration original wait/EOF/close or no-acquisition facts differ")
        require(all(type(case[field]) is int for field in
                    ("requestFrames", "responseFrames", "stdoutBytes", "stderrBytes", "cleanupElapsedMs"))
                and 10_000 <= case["cleanupElapsedMs"] <= 60_000
                and case["requestFrames"] == (3 if terminal else 0)
                and case["responseFrames"] == (3 if terminal else 0) and case["stderrBytes"] == 0,
                "Configuration clock or frame accounting differs")
        if terminal:
            require(0 < case["stdoutBytes"] <= 12 * 1024 * 1024
                    and type(case["terminalSeq"]) is int and case["terminalSeq"] == 2
                    and case["outcome"] == {"effect": "committed", "journal": "clean", "resources": "settled", "reason": "none"},
                    "Configuration late committed result was lost or replaced")
        else:
            require(case["stdoutBytes"] == 0 and case["terminalSeq"] is None and case["outcome"] is None,
                    "Never-started configuration owner fabricated a core result")
    return receipt


def validate_config_transaction_eof_receipt(receipt: object, *, source_sha: str, platform: str,
                                           source_hashes: dict[str, str], python_hash: str) -> dict:
    require(isinstance(receipt, dict) and set(receipt) == {
                "schemaVersion", "scope", "status", "allOwnersSettled", "failureCode", "bindings", "cases", "notVerified"}
            and type(receipt["schemaVersion"]) is int and receipt["schemaVersion"] == 1
            and receipt["scope"] == "configuration-transaction-eof-hosted-v1"
            and receipt["status"] == "passed" and receipt["failureCode"] is None
            and receipt["allOwnersSettled"] is True
            and receipt["notVerified"] == list(CONFIG_OWNER_NOT_VERIFIED),
            "Configuration transaction EOF fixture did not pass its exact scope")
    bindings = receipt["bindings"]
    require(isinstance(bindings, dict), "Configuration EOF bindings differ")
    payloads = bindings.get("payloadHashes")
    base_payloads = {"draft", "createConfig", "createIgnore", "noOpConfig", "noOpIgnore", "unrelated"}
    require(isinstance(payloads, dict) and set(payloads) == base_payloads | {"eofDraft", "eofConfig", "eofInitialIgnore", "eofIgnore"}
            and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in payloads.values()),
            "Configuration EOF payload inventory differs")
    # Older healthy/lifecycle receipts retain their exact six-payload contract.
    # Only this new scope carries the extra shim and changed transaction inputs.
    validate_config_owner_bindings({**bindings, "payloadHashes": {key: payloads[key] for key in base_payloads}},
        source_sha=source_sha, platform=platform, source_hashes=source_hashes, python_hash=python_hash)
    cases = receipt["cases"]
    require(isinstance(cases, list) and len(cases) == 2, "Configuration transaction EOF case inventory differs")
    fields = {"name", "evidenceKind", "bootstrapMode", "nativePhase", "nativeFinality", "nativeReason", "applySubmitted",
              "lateSettled", "ownerDisabled", "outcome", "terminalSeq", "preparedCorrelation", "closeBeforeActiveDeadline",
              "controlRecords", "boundary", "actualStdinEof", "eofReadCount", "nonemptyReadCount", "readErrorCount",
              "originalCheckpoint", "committedPublication", "rolledBackPublication", "terminalDurable", "fixedRecovery",
              "journalClean", "originalsPreserved", "payloadsInstalled", "modesPreserved", "unrelatedPreserved",
              "journalAbsent", "fixtureFilesSettled", "requestFrames", "responseFrames", "stdoutBytes", "stderrBytes",
              "forceAttempted", *CONFIG_OWNER_FINALITY}
    for case, name, boundary, checkpoint, committed in zip(cases,
            ("precommit-eof", "postcommit-eof"), ("before-COMMITTED", "after-durable-COMMITTED"),
            ("publisher-entry", "descriptor-close"), (False, True), strict=True):
        require(isinstance(case, dict) and set(case) == fields and case["name"] == name
                and case["evidenceKind"] == "real-stdin-eof-at-controlled-transaction-boundary"
                and case["bootstrapMode"] == "instrumented-genuine-engine"
                and case["nativePhase"] == "final" and case["nativeFinality"] == "settled" and case["nativeReason"] == "cancelled"
                and case["lateSettled"] is False and case["ownerDisabled"] is False and case["forceAttempted"] is False
                and case["boundary"] == boundary and case["originalCheckpoint"] == checkpoint,
                "Configuration transaction EOF original owner facts differ")
        require(all(case[field] is True for field in (*CONFIG_OWNER_FINALITY, "applySubmitted", "preparedCorrelation",
                    "closeBeforeActiveDeadline", "actualStdinEof", "terminalDurable", "fixedRecovery", "journalClean",
                    "modesPreserved", "unrelatedPreserved", "journalAbsent", "fixtureFilesSettled"))
                and case["committedPublication"] is committed and case["rolledBackPublication"] is (not committed)
                and case["originalsPreserved"] is (not committed) and case["payloadsInstalled"] is committed,
                "Configuration transaction EOF recovery or original settlement differs")
        terminal = "COMMITTED" if committed else "ROLLED_BACK"
        control_records = (f"MRK_CONFIG_EOF_V1 {name} boundary={boundary}\n"
            f"MRK_CONFIG_EOF_V1 {name} eof=1 nonempty=0 readErrors=0 checkpoint={checkpoint} "
            f"applied=1 committed={int(committed)} rolledBack={int(not committed)} terminal={terminal} "
            "durable=1 recovery=1 clean=1 settled=1 cancelled=1\n")
        require(all(type(case[field]) is int for field in ("terminalSeq", "controlRecords", "eofReadCount",
                    "nonemptyReadCount", "readErrorCount", "requestFrames", "responseFrames", "stdoutBytes", "stderrBytes"))
                and case["terminalSeq"] == 2 and case["controlRecords"] == 2 and case["eofReadCount"] == 1
                and case["nonemptyReadCount"] == 0 and case["readErrorCount"] == 0
                and case["requestFrames"] == 3 and case["responseFrames"] == 3
                and 0 < case["stdoutBytes"] <= 12 * 1024 * 1024
                and case["stderrBytes"] == len(control_records.encode("ascii")),
                "Configuration transaction EOF control/frame accounting differs")
        require(case["outcome"] == {"effect": "committed" if committed else "rolled_back", "journal": "clean",
                                   "resources": "settled", "reason": "cancelled"},
                "Configuration transaction EOF result cannot be normal Saved")
    return receipt


def config_transaction_eof_receipt(context: dict) -> dict:
    path = Path(context["root"]) / "config-transaction-eof/receipt.json"
    ordinary(path)
    require(0 < path.stat().st_size <= 64 * 1024, "Configuration transaction EOF receipt exceeded its bound")
    with path.open("rb") as stream:
        data = stream.read(64 * 1024 + 1)
    require(len(data) <= 64 * 1024, "Configuration transaction EOF receipt changed")
    source = Path(context["source"])
    return validate_config_transaction_eof_receipt(json.loads(data), source_sha=context["sourceSha"], platform=context["platform"],
        source_hashes={name: hash_file(source / relative) for name, relative in CONFIG_TRANSACTION_EOF_SOURCES.items()},
        python_hash=hash_file(Path(context["python"])))


def config_owner_receipt(context: dict) -> dict:
    path = Path(context["root"]) / "config-owner/receipt.json"
    ordinary(path)
    require(0 < path.stat().st_size <= 64 * 1024, "Configuration owner receipt exceeded its bound")
    with path.open("rb") as stream:
        data = stream.read(64 * 1024 + 1)
    require(len(data) <= 64 * 1024, "Configuration owner receipt changed")
    source = Path(context["source"])
    return validate_config_owner_receipt(json.loads(data), source_sha=context["sourceSha"], platform=context["platform"],
        source_hashes={name: hash_file(source / relative) for name, relative in CONFIG_OWNER_SOURCES.items()},
        python_hash=hash_file(Path(context["python"])))


def config_loss_receipt(context: dict, kind: str) -> dict:
    require(kind in ("driver-loss", "watchdog-loss"), "Unknown management-loss partition")
    path = Path(context["root"]) / ("config-" + kind) / "receipt.json"
    ordinary(path)
    require(0 < path.stat().st_size <= 64 * 1024, "Management-loss receipt exceeded its bound")
    with path.open("rb") as stream:
        data = stream.read(64 * 1024 + 1)
    require(len(data) <= 64 * 1024, "Management-loss receipt changed")
    source = Path(context["source"])
    return validate_config_loss_receipt(json.loads(data), kind, source_sha=context["sourceSha"], platform=context["platform"],
        source_hashes={name: hash_file(source / relative) for name, relative in CONFIG_OWNER_SOURCES.items()},
        python_hash=hash_file(Path(context["python"])))


def config_delta_receipt(context: dict, kind: str) -> dict:
    require(kind in {"stop", "terminal-deadline", "startup-stop"}, "Unknown configuration lifecycle partition")
    path = Path(context["root"]) / ("config-" + kind) / "receipt.json"
    ordinary(path)
    require(0 < path.stat().st_size <= 64 * 1024, "Configuration lifecycle receipt exceeded its bound")
    with path.open("rb") as stream:
        data = stream.read(64 * 1024 + 1)
    require(len(data) <= 64 * 1024, "Configuration lifecycle receipt changed")
    source = Path(context["source"])
    return validate_config_delta_receipt(json.loads(data), kind, source_sha=context["sourceSha"], platform=context["platform"],
        source_hashes={name: hash_file(source / relative) for name, relative in CONFIG_OWNER_SOURCES.items()},
        python_hash=hash_file(Path(context["python"])))


def phase_receipt(context: dict, name: str, checks: list[str], *, node: str | None = None,
                  scope: str = "passive-development-foundation-only") -> None:
    # Only called after the fixed phase and final source check actually succeed.
    # Missing files on failed/skipped phases cannot become passing evidence.
    value = {
        "schemaVersion": 1, "scope": scope, "phase": name,
        "status": "passed", "sourceSha": context["sourceSha"], "platform": context["platform"],
        "rust": {"release": RUST, "target": TARGETS[context["platform"]]}, "node": node,
        "checks": [{"check": check, "exitCode": 0} for check in checks],
    }
    if context.get("executionScope") == COMPILE_SCOPE:
        require(name in COMPILE_CHECKS and scope == "passive-development-foundation-only",
                "Compiler-only phase cannot produce native evidence")
        value.update(scope=COMPILE_EVIDENCE_SCOPE,
                     **{key: context[key] for key in ("workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt")})
        validate_compile_receipt(value, context, name)
    write_json(Path(context["root"]) / f"{name}-checks.json", value)


def prepare(platform: str, scope: str = BOUNDARY_SCOPE) -> None:
    admit_phase(scope, "prepare")
    binding = compile_workflow_binding(os.environ) if scope == COMPILE_SCOPE else {}
    source = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    sha = os.environ["GITHUB_SHA"]
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "Invalid source SHA")
    for relative in ("desktop/node_modules", "desktop/dist", "desktop/src-tauri/target", "desktop/src-tauri/gen"):
        require(not (source / relative).exists() and not (source / relative).is_symlink(),
                "Fresh checkout contains an existing generated output")
    no_cargo_configuration((source / "desktop/src-tauri", source / "desktop", source, *source.parents,
                            temp, *temp.parents))
    for ancestor in (source / "desktop", source, *source.parents):
        require(not (ancestor / ".npmrc").exists(), "Ambient npm project configuration is not admitted")
    root = Path(tempfile.mkdtemp(prefix="mrk-desktop-foundation-", dir=temp))
    no_cargo_configuration((root,))
    for name in ("home", "cargo", "rustup", "tmp", "target", "native", "config-owner", "config-driver-loss", "config-watchdog-loss",
                 "config-stop", "config-terminal-deadline", "config-startup-stop", "config-transaction-eof",
                 "appdata", "localappdata", "npm-cache"):
        (root / name).mkdir(mode=0o700)
    for name in ("npmrc-user", "npmrc-global", "gitconfig-empty"):
        (root / name).touch(mode=0o600, exist_ok=False)
    git = shutil.which("git")
    rustup = shutil.which("rustup")
    require(git is not None and rustup is not None, "Hosted compiler tools unavailable")
    environment = clean_environment(root)
    require(run([git, "rev-parse", "HEAD"], check="source-head", cwd=source, env=environment, timeout=15, capture=True) == sha,
            "Event and checkout source differ")
    tree = run([git, "rev-parse", "HEAD^{tree}"], check="source-tree", cwd=source, env=environment, timeout=15, capture=True)
    inventory = []
    total = 0
    package = source / "src/mobile_release"
    with zipfile.ZipFile(root / "core.zip", "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(package.rglob("*")):
            require(not path.is_symlink(), "Core input contains a symbolic link")
            if path.is_dir():
                continue
            ordinary(path)
            require(path.suffix in {".py", ".json", ".pem"}, "Unexpected/generated core input")
            require(len(inventory) < 2048 and path.stat().st_size <= 8 * 1024 * 1024, "Core input bound exceeded")
            data = path.read_bytes()
            total += len(data)
            require(total <= 32 * 1024 * 1024, "Core aggregate bound exceeded")
            name = path.relative_to(source / "src").as_posix()
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(member, data, compress_type=zipfile.ZIP_DEFLATED)
            inventory.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    context = {"root": str(root), "source": str(source), "sourceSha": sha, "platform": platform,
               "executionScope": scope,
               "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
               "git": git, "rustup": rustup, "python": str(Path(sys.executable).resolve(strict=True))}
    context.update(binding)
    workflow = COMPILE_WORKFLOW if scope == COMPILE_SCOPE else ".github/workflows/desktop-foundation.yml"
    if scope == COMPILE_SCOPE:
        context["workflowSha256"] = hash_file(source / workflow)
    source_unchanged(context)
    write_json(root / "context.json", context)
    public = {
        "scope": COMPILE_EVIDENCE_SCOPE if scope == COMPILE_SCOPE else "passive-development-foundation-only", "sourceSha": sha, "sourceTree": tree,
        "workflowSha256": hash_file(source / workflow),
        "runId": context["runId"], "attempt": context["attempt"], "platform": platform,
        "image": os.environ.get("ImageOS", "") + "/" + os.environ.get("ImageVersion", ""),
        # Version only (never hostname): future kernel-bound runtime admission
        # must use actual native observations, not infer a kernel from ImageOS.
        "kernelRelease": os.uname().release if platform in {"linux", "macos"} else None,
        "architecture": os.environ["RUNNER_ARCH"], "python": PYTHON, "expectedRust": RUST,
        "coreZipSha256": hash_file(root / "core.zip"), "coreFiles": inventory,
        "bootstrapSha256": hash_file(source / "desktop/engine_bootstrap.py"),
        "cargoLockSha256": hash_file(source / "desktop/src-tauri/Cargo.lock"),
        "npmLockSha256": hash_file(source / "desktop/package-lock.json"),
        "configBootstrapSha256": hash_file(source / "desktop/config_edit_bootstrap.py"),
        "configFixtureSha256": hash_file(source / "tests/native_desktop_config.py"),
        "configOwnerFixtureSha256": hash_file(source / "desktop/src-tauri/src/edit_hosted_tests.rs"),
        "notQualified": ["production-runtime", "native-GUI", "native-document-lifecycle", "configuration-saving",
                         "Windows-filesystem", "installers", "release-operations"],
    }
    if scope == COMPILE_SCOPE:
        public.update(binding)
        public["notQualified"].append("test-execution")
    write_json(root / "public-bindings.json", public)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8", newline="\n") as output:
        output.write(f"root={root}\n")
    print("Prepared bounded source ZIP and source-bound synthetic check inputs.")


def load_context(platform: str, scope: str = BOUNDARY_SCOPE) -> dict:
    root = Path(os.environ["MRK_DESKTOP_CI_ROOT"])
    require(root.is_absolute() and root.name.startswith("mrk-desktop-foundation-")
            and root.parent == Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
            and not root.is_symlink(), "Unrecognized task root")
    ordinary(root / "context.json")
    context = json.loads((root / "context.json").read_text(encoding="utf-8"))
    require(context["root"] == str(root) and context["platform"] == platform and context.get("executionScope") == scope
            and context["sourceSha"] == os.environ["GITHUB_SHA"]
            and context["runId"] == os.environ["GITHUB_RUN_ID"]
            and context["attempt"] == os.environ["GITHUB_RUN_ATTEMPT"], "Task context differs")
    if scope == COMPILE_SCOPE:
        binding = compile_workflow_binding(os.environ)
        require(all(context.get(key) == value for key, value in binding.items())
                and context.get("workflowSha256") == hash_file(Path(context["source"]) / COMPILE_WORKFLOW),
                "Compiler task workflow binding changed")
    return context


def tools(context: dict, environment: dict[str, str]) -> tuple[str, str]:
    root = Path(context["root"])
    cargo = run([context["rustup"], "which", "--toolchain", RUST, "cargo"], cwd=root,
                check="cargo-selection", env=environment, timeout=15, capture=True)
    rustc = run([context["rustup"], "which", "--toolchain", RUST, "rustc"], cwd=root,
                check="rustc-selection", env=environment, timeout=15, capture=True)
    require(all(Path(value).is_absolute() and Path(value).is_file() for value in (cargo, rustc)),
            "Selected compiler paths unavailable")
    version = run([rustc, "-vV"], check="rust-version-target", cwd=root, env=environment, timeout=15, capture=True)
    require(f"release: {RUST}\n" in version + "\n"
            and f"host: {TARGETS[context['platform']]}\n" in version + "\n", "Compiler host/version differs")
    environment["RUSTC"] = rustc
    environment["PATH"] = str(Path(cargo).parent) + os.pathsep + environment["PATH"]
    return cargo, rustc


def clean_compile(context: dict) -> None:
    """Only positively completed compiler work; no fabricated native receipts."""
    require(context.get("executionScope") == COMPILE_SCOPE, "Wrong compiler cleanup scope")
    root, source = Path(context["root"]), Path(context["source"])
    for phase_name in COMPILE_CHECKS:
        path = root / f"{phase_name}-checks.json"
        ordinary(path)
        require(0 < path.stat().st_size <= 16384, "Compiler phase receipt exceeds its bound")
        with path.open("rb") as stream:
            raw = stream.read(16385)
        validate_compile_receipt(parse_compile_receipt(raw), context, phase_name)
    nonempty = set()
    for name in EMPTY_NATIVE_DIRECTORIES:
        directory = root / name
        require(directory.is_dir() and not directory.is_symlink()
                and not getattr(directory.lstat(), "st_file_attributes", 0) & 0x400,
                "Compiler native placeholder is no longer an ordinary directory")
        if any(directory.iterdir()):
            nonempty.add(name)
    validate_compile_inventory({path.name for path in root.iterdir()}, nonempty)
    # Validate the complete deletion roster before removing any of it. All were
    # created by prepare/acquire/compile in this fresh hosted job, never user data.
    directories = [source / relative for relative in ("desktop/node_modules", "desktop/dist", "desktop/src-tauri/gen")]
    directories.extend(root / name for name in COMPILER_DIRECTORIES)
    for directory in directories:
        require(directory.is_dir() and not directory.is_symlink()
                and not getattr(directory.lstat(), "st_file_attributes", 0) & 0x400,
                "Task-owned compiler output directory differs")
    for name in COMPILER_PRIVATE_FILES + COMPILE_PUBLIC_FILES:
        ordinary(root / name)
    for directory in directories:
        shutil.rmtree(directory)
    for name in EMPTY_NATIVE_DIRECTORIES:
        (root / name).rmdir()
    for name in COMPILER_PRIVATE_FILES:
        (root / name).unlink()
    require({path.name for path in root.iterdir()} == set(COMPILE_PUBLIC_FILES), "Unexpected output after compiler cleanup")
    print("Removed settled compiler-only outputs; preserved exactly three public receipts. No native qualification.")


def phase(name: str, platform: str, scope: str = BOUNDARY_SCOPE) -> None:
    admit_phase(scope, name)
    context = load_context(platform, scope)
    root, source = Path(context["root"]), Path(context["source"])
    environment = clean_environment(root)
    # The owner fixture binds its compiled source to this exact event commit.
    # Compile and test must use the same value; no None/ambient/latest fallback.
    environment["GITHUB_SHA"] = context["sourceSha"]
    manifest = source / "desktop/src-tauri/Cargo.toml"
    source_unchanged(context)
    no_cargo_configuration((root, *root.parents))
    if name == "clean" and scope == COMPILE_SCOPE:
        clean_compile(context)
        return
    if name == "acquire":
        run([context["rustup"], "toolchain", "install", RUST, "--profile", "minimal", "--no-self-update"],
            check="rust-toolchain-install", cwd=root, env=environment, timeout=600)
        cargo, _ = tools(context, environment)
        features = "desktop-shell,development-runtime"
        # Metadata filters acquisition to this platform and active feature graph.
        with (root / "metadata.json").open("x", encoding="utf-8") as output:
            run([cargo, "metadata", "--locked", "--format-version", "1", "--no-default-features",
                 "--features", features, "--filter-platform", TARGETS[platform],
                 "--manifest-path", str(manifest)], check="locked-platform-metadata", cwd=root,
                env=environment, timeout=600, output=output)
        node = shutil.which("node")
        require(node is not None, "Selected Node unavailable")
        observed_node = run([node, "--version"], check="node-version", cwd=root, env=environment, timeout=15, capture=True)
        require(observed_node == NODE, "Selected Node version differs")
        npm = (Path(node).parent / "node_modules/npm/bin/npm-cli.js" if platform == "windows" else
               Path(node).parent.parent / "lib/node_modules/npm/bin/npm-cli.js")
        ordinary(npm)
        run([node, "--max-old-space-size=768", str(npm), "ci", "--ignore-scripts", "--no-audit", "--no-fund",
             "--userconfig", str(root / "npmrc-user"), "--globalconfig", str(root / "npmrc-global"),
             "--cache", str(root / "npm-cache"), "--registry", "https://registry.npmjs.org/"],
            check="npm-locked-no-scripts", cwd=source / "desktop", env=environment, timeout=300)
        source_unchanged(context)
        phase_receipt(context, name, ["rust-toolchain-install", "rust-version-target", "locked-platform-metadata"]
                      + ["node-version", "npm-locked-no-scripts"], node=observed_node)
        return
    cargo, _ = tools(context, environment)
    common = ["--locked", "--offline", "--jobs", "1", "--no-default-features",
              "--target", TARGETS[platform], "--manifest-path", str(manifest), "--target-dir", str(root / "target")]
    if name == "compile":
        run([cargo, "test", *common, "--lib", "--no-run", "--features", "development-runtime"],
            check="headless-test-compile-only", cwd=root, env=environment, timeout=600)
        node = shutil.which("node")
        require(node is not None, "Node unavailable after setup")
        observed_node = run([node, "--version"], check="node-version", cwd=root, env=environment, timeout=15, capture=True)
        require(observed_node == NODE, "Selected Node version changed")
        desktop = source / "desktop"
        run([node, "--max-old-space-size=768", "node_modules/typescript/bin/tsc", "--noEmit", "-p", "tsconfig.json"],
            check="typescript-no-emit", cwd=desktop, env=environment, timeout=60)
        run([node, "--max-old-space-size=768", "node_modules/vite/bin/vite.js", "build", "--config",
             str(desktop / "vite.config.mjs"), "--configLoader", "native", "--outDir", str(desktop / "dist")],
            check="vite-assets", cwd=desktop, env=environment, timeout=90)
        run([cargo, "build", *common, "--features", "desktop-shell,development-runtime",
             "--bin", "mobile-release-kit-desktop"], check="tauri-debug-compile-only", cwd=root, env=environment, timeout=1500)
        source_unchanged(context)
        phase_receipt(context, name, ["rust-version-target", "headless-test-compile-only"]
                      + ["node-version", "typescript-no-emit", "vite-assets", "tauri-debug-compile-only"], node=observed_node)
    elif name == "native":
        environment.update(MRK_DESKTOP_DEV_PYTHON=context["python"], MRK_DESKTOP_DEV_CORE=str(source / "src"),
                           MRK_DESKTOP_TEST_ROOT=str(root / "native"), MRK_DESKTOP_TEST_CORE_ZIP=str(root / "core.zip"),
                           MRK_DESKTOP_HOSTED_CHECKS="passive-v1", GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                           GITHUB_SHA=context["sourceSha"])
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", NATIVE_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="passive-native-contract", cwd=root, env=environment, timeout=300)
        source_unchanged(context)
        native_receipt(context)
        phase_receipt(context, name, ["rust-version-target", NATIVE_TEST, "native-receipt-acceptance"])
    elif name == "config-owner":
        require(platform in {"linux", "macos"}, "POSIX configuration fixtures are not Windows support")
        native_receipt(context)
        environment.update(MRK_DESKTOP_DEV_PYTHON=context["python"], MRK_DESKTOP_DEV_CORE=str(source / "src"),
                           MRK_DESKTOP_EDIT_TEST_ROOT=str(root / "config-owner"),
                           MRK_DESKTOP_EDIT_HOSTED_CHECKS="configuration-v1", MRK_DESKTOP_EDIT_SOURCE_SHA=context["sourceSha"],
                           GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                           RUNNER_OS="Linux" if platform == "linux" else "macOS",
                           RUNNER_TEMP=str(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)))
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", CONFIG_OWNER_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="config-owner-native-contract", cwd=root, env=environment, timeout=180)
        source_unchanged(context)
        config_owner_receipt(context)
        phase_receipt(context, name, [CONFIG_OWNER_TEST, "configuration-original-resource-receipt-acceptance"],
                      scope="configuration-owner-native-only-not-desktop-enablement")
    elif name == "config-task-loss":
        require(platform in {"linux", "macos"}, "POSIX configuration fixtures are not Windows support")
        native_receipt(context)
        config_owner_receipt(context)
        environment.update(MRK_DESKTOP_DEV_PYTHON=context["python"], MRK_DESKTOP_DEV_CORE=str(source / "src"),
                           MRK_DESKTOP_EDIT_HOSTED_CHECKS="configuration-v1", MRK_DESKTOP_EDIT_SOURCE_SHA=context["sourceSha"],
                           GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                           RUNNER_OS="Linux" if platform == "linux" else "macOS",
                           RUNNER_TEMP=str(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)))
        environment["MRK_DESKTOP_EDIT_TEST_ROOT"] = str(root / "config-driver-loss")
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", CONFIG_DRIVER_LOSS_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="config-driver-loss-native-contract", cwd=root, env=environment, timeout=90)
        config_loss_receipt(context, "driver-loss")
        # The original prior subprocess has exited/waited and its underlying
        # native resources are proved settled. Its management Unknown/root is
        # retained; the next process receives a different exclusive fixture root.
        environment["MRK_DESKTOP_EDIT_TEST_ROOT"] = str(root / "config-watchdog-loss")
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", CONFIG_WATCHDOG_LOSS_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="config-watchdog-loss-native-contract", cwd=root, env=environment, timeout=90)
        config_loss_receipt(context, "watchdog-loss")
        source_unchanged(context)
        phase_receipt(context, name, [CONFIG_DRIVER_LOSS_TEST, CONFIG_WATCHDOG_LOSS_TEST, "native-resources-settled-management-unknown"],
                      scope="controlled-management-loss-only-not-normal-owner-settlement")
    elif name == "config-owner-delta":
        require(platform in {"linux", "macos"}, "POSIX configuration fixtures are not Windows support")
        native_receipt(context)
        config_owner_receipt(context)
        config_loss_receipt(context, "driver-loss")
        config_loss_receipt(context, "watchdog-loss")
        environment.update(MRK_DESKTOP_DEV_PYTHON=context["python"], MRK_DESKTOP_DEV_CORE=str(source / "src"),
                           MRK_DESKTOP_EDIT_HOSTED_CHECKS="configuration-v1", MRK_DESKTOP_EDIT_SOURCE_SHA=context["sourceSha"],
                           GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                           RUNNER_OS="Linux" if platform == "linux" else "macOS",
                           RUNNER_TEMP=str(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)))
        environment["MRK_DESKTOP_EDIT_TEST_ROOT"] = str(root / "config-stop")
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", CONFIG_STOP_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="config-stop-native-contract", cwd=root, env=environment, timeout=60)
        config_delta_receipt(context, "stop")
        # Each original subprocess must return and its actual resource facts
        # must pass before the next fixed process/root is admitted. The clock
        # cases retain sticky Unknown, not ordinary successful-save finality.
        environment["MRK_DESKTOP_EDIT_TEST_ROOT"] = str(root / "config-terminal-deadline")
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", CONFIG_TERMINAL_DEADLINE_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="config-terminal-deadline-native-contract", cwd=root, env=environment, timeout=90)
        config_delta_receipt(context, "terminal-deadline")
        environment["MRK_DESKTOP_EDIT_TEST_ROOT"] = str(root / "config-startup-stop")
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", CONFIG_STARTUP_STOP_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="config-startup-stop-native-contract", cwd=root, env=environment, timeout=60)
        config_delta_receipt(context, "startup-stop")
        source_unchanged(context)
        phase_receipt(context, name, [CONFIG_STOP_TEST, CONFIG_TERMINAL_DEADLINE_TEST, CONFIG_STARTUP_STOP_TEST,
                                     "original-resource-clock-and-stop-receipt-acceptance"],
                      scope="configuration-clock-and-stop-controls-only-not-desktop-enablement")
    elif name == "config-transaction-eof":
        require(platform in {"linux", "macos"}, "POSIX configuration fixtures are not Windows support")
        native_receipt(context)
        config_owner_receipt(context)
        config_loss_receipt(context, "driver-loss")
        config_loss_receipt(context, "watchdog-loss")
        for kind in ("stop", "terminal-deadline", "startup-stop"):
            config_delta_receipt(context, kind)
        environment.update(MRK_DESKTOP_DEV_PYTHON=context["python"], MRK_DESKTOP_DEV_CORE=str(source / "src"),
                           MRK_DESKTOP_EDIT_TEST_ROOT=str(root / "config-transaction-eof"),
                           MRK_DESKTOP_EDIT_HOSTED_CHECKS="configuration-v1", MRK_DESKTOP_EDIT_SOURCE_SHA=context["sourceSha"],
                           GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                           RUNNER_OS="Linux" if platform == "linux" else "macOS",
                           RUNNER_TEMP=str(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)))
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", CONFIG_TRANSACTION_EOF_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="config-transaction-eof-native-contract", cwd=root, env=environment, timeout=90)
        source_unchanged(context)
        config_transaction_eof_receipt(context)
        phase_receipt(context, name, [CONFIG_TRANSACTION_EOF_TEST, "transaction-eof-original-resource-receipt-acceptance"],
                      scope="controlled-transaction-eof-only-not-desktop-enablement")
    elif name == "config-core":
        require(platform in {"linux", "macos"}, "POSIX configuration fixtures are not Windows support")
        native_receipt(context)
        config_owner_receipt(context)
        config_loss_receipt(context, "driver-loss")
        config_loss_receipt(context, "watchdog-loss")
        for kind in ("stop", "terminal-deadline", "startup-stop"):
            config_delta_receipt(context, kind)
        config_transaction_eof_receipt(context)
        environment.update(MRK_DESKTOP_CONFIG_NATIVE="1", GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                           RUNNER_OS="Linux" if platform == "linux" else "macOS",
                           RUNNER_TEMP=str(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)))
        fixture = [context["python"], "-I", "-S", "-B", str(source / "tests/native_desktop_config.py"),
                   "--task-root", str(root), "--case"]
        # Each return includes the original interpreter's wait. Validate its
        # complete positive settlement contract before admitting the next one.
        with (root / "config-ordinary.json").open("x", encoding="utf-8") as output:
            run([*fixture, "ordinary"], check="config-core-ordinary", cwd=root, env=environment, timeout=90, output=output)
        config_receipt(context, "ordinary")
        with (root / "config-committed-fsync.json").open("x", encoding="utf-8") as output:
            run([*fixture, "committed-fsync"], check="config-core-committed-fsync", cwd=root, env=environment, timeout=45, output=output)
        config_receipt(context, "committed-fsync")
        with (root / "config-committed-close.json").open("x", encoding="utf-8") as output:
            run([*fixture, "committed-close"], check="config-core-committed-close", cwd=root, env=environment, timeout=45, output=output)
        config_receipt(context, "committed-close")
        # This last control deliberately retains uncertainty. No further native
        # fixture/owner is started, and no retaining root is adopted for cleanup.
        source_unchanged(context)
        phase_receipt(context, name, ["config-core-ordinary", "config-core-committed-fsync", "config-core-committed-close"],
                      scope="configuration-core-native-only-not-desktop-enablement")
    else:
        require(name == "clean", "Unknown fixed phase")
        native_receipt(context)
        retained = False
        if platform in {"linux", "macos"}:
            config_owner_receipt(context)
            config_loss_receipt(context, "driver-loss")
            config_loss_receipt(context, "watchdog-loss")
            for kind in ("stop", "terminal-deadline", "startup-stop"):
                config_delta_receipt(context, kind)
            config_transaction_eof_receipt(context)
            for partition in CONFIG_PARTITIONS:
                config_receipt(context, partition)
            retained = True  # Management-loss roots stay retained even after proved native settlement.
        # Only fresh outputs whose absence prepare() required. No dependency or
        # file outside this exact job root/fresh checkout is selected for removal.
        for relative in ("desktop/node_modules", "desktop/dist", "desktop/src-tauri/gen"):
            output = source / relative
            require(not output.is_symlink(), "Generated output became a link")
            if output.exists():
                shutil.rmtree(output)
        if retained:
            for name in ("cargo", "rustup", "target", "npm-cache", "tmp", "home", "appdata", "localappdata"):
                output = root / name
                require(output.is_dir() and not output.is_symlink(), "Task-owned compiler directory differs")
                shutil.rmtree(output)
            print("Removed settled compiler/dependency outputs; retained fixture journals/uncertainty for hosted VM disposal.")
        else:
            shutil.rmtree(root)
            print("Removed settled task-owned compiler, dependency and fixture outputs.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "acquire", "compile", "native", "config-owner", "config-task-loss", "config-owner-delta", "config-transaction-eof", "config-core", "clean"))
    args = parser.parse_args()
    os.umask(0o077)
    print(f"Starting fixed desktop phase: {args.phase}", flush=True)
    try:
        scope = os.environ.get("MRK_DESKTOP_HOSTED_CHECKS", "")
        admit_phase(scope, args.phase)
        platform = admitted_host()
        prepare(platform, scope) if args.phase == "prepare" else phase(args.phase, platform, scope)
    except Exception as error:
        reason = str(error) if isinstance(error, CheckFailure) else type(error).__name__
        print(f"Desktop {args.phase} failed: {reason}. Preserve evidence; no native or product success is implied.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
