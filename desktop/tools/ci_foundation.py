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
NATIVE_TEST = "supervisor::hosted_tests::passive_hosted_contract"
WINDOWS_SNAPSHOT_TEST = "supervisor::hosted_tests::windows_static_snapshot_hosted_contract"
FOUNDATION_SCOPE = "passive-v1"
WINDOWS_SNAPSHOT_SCOPE = "windows-snapshot-v1"
WINDOWS_SNAPSHOT_PUBLIC_SCOPE = "windows-static-snapshot-native-only-not-desktop-enablement"
WINDOWS_SNAPSHOT_PHASES = frozenset({"prepare", "acquire", "compile", "windows-snapshot", "clean"})
WINDOWS_SNAPSHOT_RECEIPT_SCOPE = "windows-static-snapshot-native-v1"
WINDOWS_SDK_VERSION = "10.0.26100.0"
WINDOWS_SDK_HEADERS = tuple(sorted((
    "shared/ntdef.h", "shared/ntstatus.h", "shared/winerror.h", "um/winternl.h", "um/winnt.h",
    "um/minwinbase.h", "um/WinBase.h", "um/winioctl.h", "um/ioapiset.h", "um/fileapi.h",
    "um/securitybaseapi.h", "um/aclapi.h",
)))
WINDOWS_SNAPSHOT_SOURCES = tuple(sorted((
    "src/mobile_release/api/_snapshot_windows_native.py", "src/mobile_release/api/_snapshot_windows.py",
    "src/mobile_release/api/_snapshot.py", "src/mobile_release/api/__init__.py",
    "tests/desktop/test_windows_snapshot.py", "tests/desktop/test_api.py", "docs/desktop.md",
    "desktop/src-tauri/runtime-contract.md", "tests/native_desktop_snapshot_windows.py",
    "desktop/src-tauri/src/hosted_tests.rs", "desktop/src-tauri/src/supervisor.rs",
    "desktop/tools/ci_foundation.py", ".github/workflows/desktop-foundation.yml",
    "tests/desktop/test_ci_foundation_contract.py", "src/mobile_release/__init__.py",
    "src/mobile_release/_desktop_engine.py", "src/mobile_release/api/contracts.py",
    "src/mobile_release/api/_json.py", "src/mobile_release/config.py", "src/mobile_release/discovery.py",
    "src/mobile_release/init_transaction.py", "src/mobile_release/errors.py", "desktop/engine_bootstrap.py",
    "desktop/src-tauri/src/runtime.rs", "desktop/src-tauri/src/protocol.rs", "desktop/src-tauri/src/error.rs",
    "desktop/src-tauri/src/bridge.rs", "desktop/src-tauri/src/lib.rs", "desktop/src-tauri/build.rs",
    "desktop/src-tauri/Cargo.toml", "desktop/src-tauri/Cargo.lock",
)))
WINDOWS_SNAPSHOT_GROUPS = (
    ("W1", ("ordinary-source", "ordinary-zip", "closed-gate")),
    ("W2", ("link-children", "reparse-root", "reparse-ancestor", "short-alias", "case-alias", "case-collision",
            "subst-drive", "unc", "device", "ads")),
    ("W3", ("root-reparse-race", "config-reparse-race", "walk-reparse-race", "case-mode-race")),
    ("W4", ("acl-type", "read-eof-size", "entry-limit", "candidate-limit", "aggregate-limit", "depth-path-limit")),
    ("W5", ("replace", "disappear", "config-disappear", "ending-metadata-case", "drive-map-change")),
    ("W6", ("oplock-release", "oplock-withhold", "pending-failstop")),
)
WINDOWS_SNAPSHOT_NOT_VERIFIED = (
    "production-windows-enablement", "production-runtime-custody", "stateful-or-descendant-backends",
    "configuration-saving", "native-gui", "installers", "mobile-builds", "stores", "atomic-snapshot",
)
WINDOWS_READER_APIS = (
    "GetCurrentProcess", "IsWow64Process2", "QueryDosDeviceW", "NtCreateFile", "GetHandleInformation",
    "GetFileType", "GetFileInformationByHandleEx", "GetVolumeInformationByHandleW", "GetFinalPathNameByHandleW",
    "ReadFile", "CloseHandle", "DeviceIoControl",
)
WINDOWS_READER_COUNTERS = (
    "acquired", "closeAttempts", "closeSucceeded", "closeFailed", "live", "maxLive", "maxBufferBytes",
    "rootOpens", "relativeOpens", "metadataChecks", "identitiesMatched", "readCalls", "readBytes", "readEof",
    "directoryCalls", "directoryRecords", "directoryEof", "outsideAcquired", "outsideReads", "outsideDescent",
    "aliasMetadataAcquired", "violations", "eventCount",
)
WINDOWS_ORIGINAL_FLAGS = (
    "inspectionJoined", "acquisitionJoined", "spawned", "waited", "writerJoined", "writerComplete",
    "stdoutEof", "stderrEof", "stdoutJoined", "stderrJoined", "driverReturned", "watchdogReturned",
    "observerReturned", "terminal", "permitReleased", "registryEmpty",
)
WINDOWS_FIXTURE_COUNTERS = ("acquired", "closeAttempts", "closeSucceeded", "closeFailed", "live", "maxLive", "maxArenaBytes")
WINDOWS_SNAPSHOT_ISSUES = frozenset({
    "config.missing", "config.invalid", "snapshot.scan-stopped", "snapshot.entry-limit", "snapshot.changed",
    "snapshot.file-limit", "snapshot.file-size", "snapshot.byte-limit", "snapshot.encoding", "snapshot.unsafe-file",
    "snapshot.unsupported", "snapshot.handle-limit", "snapshot.unreadable", "snapshot.config-output-limit",
    "snapshot.path-limit", "snapshot.link-excluded", "snapshot.depth-limit", "snapshot.container-limit",
    "snapshot.output-limit",
})
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
    "windows-snapshot-native-contract",
})


class CheckFailure(ValueError):
    """Fixed, non-secret diagnostic for an explicit check condition."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


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
            and os.environ.get("MRK_DESKTOP_HOSTED_CHECKS") in {FOUNDATION_SCOPE, WINDOWS_SNAPSHOT_SCOPE},
            "This fixed check requires an explicitly admitted disposable hosted job")
    platform = os.environ.get("MRK_DESKTOP_PLATFORM", "")
    require(platform in TARGETS and platform == {
        "linux": "linux", "darwin": "macos", "win32": "windows",
    }.get(sys.platform), "Unexpected host platform")
    require(sys.version.split()[0] == PYTHON, "Unexpected selected Python version")
    selected = Path(os.environ["MRK_PYTHON"]).resolve(strict=True)
    require(selected == Path(sys.executable).resolve(strict=True), "Python setup output differs")
    admitted_scope(platform)
    return platform


def admitted_scope(platform: str) -> str:
    """Recheck the fixed workflow route, not a user-selectable execution grant."""
    scope = os.environ.get("MRK_DESKTOP_HOSTED_CHECKS", "")
    require(scope in {FOUNDATION_SCOPE, WINDOWS_SNAPSHOT_SCOPE}, "Unexpected fixed verification scope")
    windows = scope == WINDOWS_SNAPSHOT_SCOPE
    if windows:
        require(platform == "windows" and os.environ.get("RUNNER_OS") == "Windows"
                and os.environ.get("RUNNER_ARCH") == "X64", "Windows snapshot requires the native X64 job")
    sha = os.environ.get("GITHUB_SHA", "")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "Invalid exact event source")
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    if event == "push":
        expected_ref = ("refs/heads/verify/desktop-windows-snapshot" if windows
                        else "refs/heads/feature/desktop-application")
        require(os.environ.get("GITHUB_REF") == expected_ref, "Push ref and fixed verification scope differ")
    else:
        require(event == "workflow_dispatch", "Unexpected verification event")
        require(os.environ.get("MRK_DESKTOP_DISPATCH_SCOPE") == ("windows-snapshot" if windows else "foundation")
                and os.environ.get("MRK_DESKTOP_EXPECTED_SHA") == sha,
                "Dispatch scope or reviewed source differs")
    return scope


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


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError):
        raise CheckFailure("Invalid canonical fixed JSON data") from None


def closed_object(value: object, keys: set[str], diagnostic: str) -> dict:
    require(type(value) is dict and set(value) == keys, diagnostic)
    return value


def integer_between(value: object, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def sha256_value(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def bounded_json(data: bytes, limit: int) -> object:
    require(len(data) <= limit, "Fixed JSON input exceeds its bound")

    def pairs(items: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate fixed JSON field")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise CheckFailure("Nonfinite fixed JSON number")

    try:
        result = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise CheckFailure("Invalid fixed JSON encoding") from None
    pending, nodes = [(result, 0)], 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        require(depth <= 16 and nodes <= 50000, "Fixed JSON structure exceeds its bound")
        if type(value) is dict:
            pending.extend((child, depth + 1) for child in value.values())
        elif type(value) is list:
            pending.extend((child, depth + 1) for child in value)
        else:
            require(type(value) in {str, bool, int, type(None)}, "Unexpected fixed JSON scalar")
    return result


def read_bounded_json(path: Path, limit: int) -> object:
    ordinary(path)
    before = path.stat()
    require(before.st_size <= limit, "Fixed JSON file exceeds its bound")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            and len(data) == before.st_size, "Fixed JSON file changed")
    return bounded_json(data, limit)


def fixed_file_inventory(root: Path, names: tuple[str, ...]) -> list[dict]:
    inventory = []
    require(len(names) <= 2048 and all(type(name) is str and re.fullmatch(r"[A-Za-z0-9_./-]+", name) is not None
            and not name.startswith("/") and not any(part in {"", ".", ".."} for part in name.split("/")) for name in names),
            "Fixed input roster contains an unsafe path")
    require(names == tuple(sorted(set(names))), "Fixed input roster is not unique and ordered")
    for name in names:
        path = root / name
        ordinary(path)
        before = path.stat()
        require(before.st_size <= 8 * 1024 * 1024, "Fixed input file exceeds its bound")
        digest = hash_file(path)
        after = path.stat()
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "Fixed input file changed")
        inventory.append({"path": name, "sha256": digest, "size": before.st_size})
    return inventory


def windows_sdk_root() -> Path:
    # Explicit installed SDK, not latest/version discovery or an SDK download.
    program_files = Path(os.environ["ProgramFiles(x86)"])
    require(program_files.is_absolute(), "Windows Program Files root is unavailable")
    root = program_files / "Windows Kits" / "10" / "Include" / WINDOWS_SDK_VERSION
    for path in (program_files, *[program_files.joinpath(*root.relative_to(program_files).parts[:length])
                                for length in range(1, len(root.relative_to(program_files).parts) + 1)]):
        details = path.lstat()
        require(stat.S_ISDIR(details.st_mode) and not getattr(details, "st_file_attributes", 0) & 0x400,
                "The fixed installed Windows SDK is unavailable or redirected")
    return root


def windows_prepare_bindings(context: dict, public: dict) -> None:
    source = Path(context["source"])
    sdk = windows_sdk_root()
    context["sdkRoot"] = str(sdk)
    public["windowsSnapshot"] = {
        "sources": fixed_file_inventory(source, WINDOWS_SNAPSHOT_SOURCES),
        "sdk": {"version": WINDOWS_SDK_VERSION, "headers": fixed_file_inventory(sdk, WINDOWS_SDK_HEADERS)},
        "pythonSha256": hash_file(Path(context["python"])),
        "coreInventorySha256": hashlib.sha256(canonical_json(public["coreFiles"])).hexdigest(),
        "job": os.environ["GITHUB_JOB"],
    }
    require(public["windowsSnapshot"]["job"] == "windows-snapshot", "Windows job identity differs")
    public["notQualified"] = list(WINDOWS_SNAPSHOT_NOT_VERIFIED)


def windows_executable_path(value: object, *, target_root: Path) -> Path:
    """Admit the compiler's exact spelling without resolving a different file."""
    require(type(value) is str and 0 < len(value) <= 32768 and "\0" not in value
            and not any(part in {".", ".."} for part in re.split(r"[\\/]", value)),
            "Original executable artifact has an unsafe path")
    executable = Path(value)
    require(target_root.is_absolute() and executable.is_absolute() and executable != target_root
            and executable.is_relative_to(target_root) and executable.suffix == ".exe",
            "Original executable artifact left its target root")
    require(all(part not in {"", ".", ".."} and ":" not in part and "\\" not in part
                for part in executable.relative_to(target_root).parts),
            "Original executable artifact has an alternate path or stream")
    return executable


def ordinary_windows_executable(value: object, *, target_root: Path) -> Path:
    executable = windows_executable_path(value, target_root=target_root)
    relative = executable.relative_to(target_root)
    for length in range(len(relative.parts)):
        directory = target_root.joinpath(*relative.parts[:length])
        details = directory.lstat()
        require(stat.S_ISDIR(details.st_mode) and not getattr(details, "st_file_attributes", 0) & 0x400,
                "Original compiler target ancestry is redirected or unavailable")
    ordinary(executable)
    return executable


def compiled_windows_test(messages: bytes, *, target_root: Path) -> Path:
    """Read only the original successful Cargo no-run output; never scan/run bins."""
    require(len(messages) <= 16 * 1024 * 1024, "Original compiler message stream exceeds its bound")
    executables = []
    finished = 0
    for line in messages.splitlines():
        message = bounded_json(line, 1024 * 1024)
        require(type(message) is dict and type(message.get("reason")) is str, "Unexpected original compiler message")
        if message["reason"] == "compiler-artifact" and message.get("executable") is not None:
            target, profile = message.get("target"), message.get("profile")
            require(type(target) is dict and target.get("name") == "mobile_release_desktop" and target.get("kind") == ["lib"]
                    and type(profile) is dict and profile.get("test") is True
                    and message.get("features") == ["development-runtime"]
                    and type(message["executable"]) is str, "Unexpected original executable artifact")
            executable = windows_executable_path(message["executable"], target_root=target_root)
            executables.append(executable)
        elif message["reason"] == "build-finished":
            require(message.get("success") is True, "Original compiler did not finish successfully")
            finished += 1
    require(finished == 1 and len(executables) == 1, "Original no-run compilation did not identify exactly one test executable")
    return executables[0]


def windows_compile_record(context: dict, argv: list[str], messages: Path) -> dict:
    root = Path(context["root"])
    ordinary(messages)
    require(messages.stat().st_size <= 16 * 1024 * 1024, "Original compiler output exceeds its bound")
    with messages.open("rb") as stream:
        original = stream.read(16 * 1024 * 1024 + 1)
    executable = compiled_windows_test(original, target_root=root / "target")
    ordinary_windows_executable(str(executable), target_root=root / "target")
    compiled = {"schemaVersion": 1, "sourceSha": context["sourceSha"], "path": str(executable),
                "size": executable.stat().st_size, "sha256": hash_file(executable),
                "invocationSha256": hashlib.sha256(canonical_json(argv)).hexdigest()}
    write_json(root / "windows-compiled-test.json", compiled)
    return compiled


def windows_inputs(context: dict, *, create: bool) -> dict:
    root, source = Path(context["root"]), Path(context["source"])
    public = read_bounded_json(root / "public-bindings.json", 1024 * 1024)
    require(type(public) is dict and public.get("scope") == WINDOWS_SNAPSHOT_PUBLIC_SCOPE
            and public.get("sourceSha") == context["sourceSha"] and public.get("sourceTree") == context["sourceTree"]
            and public.get("runId") == context["runId"] and public.get("attempt") == context["attempt"],
            "Original Windows preparation bindings differ")
    prepared = closed_object(public.get("windowsSnapshot"), {"sources", "sdk", "pythonSha256", "coreInventorySha256", "job"},
                             "Original Windows preparation fields differ")
    sdk_root = windows_sdk_root()
    require(str(sdk_root) == context["sdkRoot"], "Original Windows SDK selection changed")
    require(fixed_file_inventory(source, WINDOWS_SNAPSHOT_SOURCES) == prepared["sources"]
            and {"version": WINDOWS_SDK_VERSION, "headers": fixed_file_inventory(sdk_root, WINDOWS_SDK_HEADERS)} == prepared["sdk"]
            and hash_file(Path(context["python"])) == prepared["pythonSha256"], "Prepared source/Python/SDK inputs changed")
    inventory = public["coreFiles"]
    require(type(inventory) is list and 0 < len(inventory) <= 2048
            and hashlib.sha256(canonical_json(inventory)).hexdigest() == prepared["coreInventorySha256"]
            and hash_file(root / "core.zip") == public["coreZipSha256"], "Prepared whole-core inventory/ZIP changed")
    names = tuple(entry["path"] for entry in inventory)
    require(fixed_file_inventory(source / "src", names) == inventory, "Prepared whole-core source members changed")
    actual_names = tuple(sorted(path.relative_to(source / "src").as_posix()
                               for path in (source / "src/mobile_release").rglob("*") if not path.is_dir()))
    require(actual_names == names, "Packaged core gained or lost members")
    compiled = closed_object(read_bounded_json(root / "windows-compiled-test.json", 8192),
                             {"schemaVersion", "sourceSha", "path", "size", "sha256", "invocationSha256"},
                             "Original compiled test record differs")
    executable = ordinary_windows_executable(compiled["path"], target_root=root / "target")
    require(type(compiled["schemaVersion"]) is int and compiled["schemaVersion"] == 1
            and compiled["sourceSha"] == context["sourceSha"] and sha256_value(compiled["invocationSha256"])
            and type(compiled["size"]) is int and compiled["size"] > 0 and sha256_value(compiled["sha256"])
            and executable.stat().st_size == compiled["size"] and hash_file(executable) == compiled["sha256"],
            "Original compiled test identity changed")
    bindings = {
        "sourceSha": context["sourceSha"], "sourceTree": context["sourceTree"], "target": TARGETS["windows"],
        "pythonVersion": PYTHON, "rustVersion": RUST, "runId": context["runId"], "attempt": context["attempt"],
        "job": prepared["job"], "image": public["image"], "architecture": "X64", "coreZipSha256": public["coreZipSha256"],
        "coreInventorySha256": prepared["coreInventorySha256"], "sources": prepared["sources"],
        "pythonSha256": prepared["pythonSha256"], "compiledTestSha256": compiled["sha256"],
        "compileInvocationSha256": compiled["invocationSha256"], "sdk": prepared["sdk"],
    }
    inputs = {"schemaVersion": 1, "scope": WINDOWS_SNAPSHOT_RECEIPT_SCOPE, "bindings": bindings,
              "coreFiles": inventory, "sdkRoot": str(sdk_root)}
    require(len(canonical_json(inputs)) <= 1024 * 1024, "Windows native inputs exceed their bound")
    path = root / "windows-snapshot-inputs.json"
    if create:
        write_json(path, inputs)
    else:
        require(canonical_json(read_bounded_json(path, 1024 * 1024)) == canonical_json(inputs),
                "Original Windows native input binding changed")
    return inputs


def windows_snapshot_receipt(context: dict) -> dict:
    inputs = windows_inputs(context, create=False)
    report = read_bounded_json(Path(context["root"]) / "windows-snapshot/receipt.json", 256 * 1024)
    return validate_windows_snapshot_receipt(report, bindings=inputs["bindings"])


def clean_windows_outputs(context: dict) -> None:
    # This is ordinary finite post-verification cleanup, NOT a cleanup remedy for
    # native failure/uncertainty. No reparse point or additional writer is admitted.
    windows_snapshot_receipt(context)
    root = Path(context["root"])
    files, directories, pending = [], [], [(root, 0)]
    count = 0
    while pending:
        directory, depth = pending.pop()
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400
                and depth <= 64, "Windows cleanup directory is redirected or too deep")
        directories.append((directory, info.st_dev, info.st_ino))
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                require(count <= 500000, "Windows task cleanup inventory exceeded its bound")
                path, metadata = Path(entry.path), entry.stat(follow_symlinks=False)
                require(not getattr(metadata, "st_file_attributes", 0) & 0x400 and not stat.S_ISLNK(metadata.st_mode),
                        "Windows task cleanup encountered a reparse point")
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append((path, depth + 1))
                else:
                    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
                            "Windows task cleanup encountered a nonordinary file")
                    files.append((path, metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns))
    # The complete non-following manifest is collected before the first deletion.
    # Expected native originals are already joined; no other task root is selected.
    for path, device, inode, size, modified in files:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not getattr(info, "st_file_attributes", 0) & 0x400
                and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) == (device, inode, size, modified),
                "Windows task cleanup file identity changed")
        path.unlink()
    for path, device, inode in sorted(directories, key=lambda item: len(item[0].parts), reverse=True):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400
                and (info.st_dev, info.st_ino) == (device, inode), "Windows task cleanup directory identity changed")
        path.rmdir()
    print("Removed only the fully settled Windows job's inventoried compiler/dependency and synthetic fixture outputs.")


def validate_windows_checks(name: str, value: object) -> None:
    """Closed case predicates, not a generic passed flag or a fixture log parser."""
    def truths(names: str) -> dict:
        return dict.fromkeys(names.split(), True)

    race = {**truths("parentIdSame mutationSucceeded originalRelativeEntry entryBeforeDeadline unsafeControlMatched "
                    "sharingWriteDenied sharingDeleteDenied reparseRestored"),
            "mutationAccess": 256, "mutationTag": 0xA0000003, "outsideAcquired": 0, "outsideReadBytes": 0}
    expected = {
        "ordinary-source": {**truths("genuineCore configExact androidExact iosExact versionNotDisclosed"),
                            "unicodeOpens": (1, 1000000), "spelling": "ordinary"},
        "ordinary-zip": {**truths("genuineCore configExact androidExact iosExact versionNotDisclosed"),
                         "unicodeOpens": (1, 1000000), "spelling": "verbatim"},
        "closed-gate": {},
        "link-children": {"fileSymlinkTag": 0xA000000C, "directorySymlinkTag": 0xA000000C,
                          "junctionTag": 0xA0000003, "hardlinkCount": (2, 1024), "hardlinkIdMatch": True,
                          "excludedReparses": (3, 10000), "hardlinkReadBytes": 0, "restoredLinks": 4},
        "reparse-root": {"junctionTag": 0xA0000003, "unsafeControlMatched": True, "rootRefused": True, "reparseRestored": 1},
        "reparse-ancestor": {"junctionTag": 0xA0000003, "unsafeControlMatched": True, "rootRefused": True, "reparseRestored": 1},
        "short-alias": {**truths("aliasObserved spellingDiffers sameObject"), "aliasAcquired": (0, 1), "aliasReadBytes": 0},
        "case-alias": {**truths("aliasObserved spellingDiffers sameObject"), "aliasAcquired": (0, 1), "aliasReadBytes": 0},
        "case-collision": {"enabledFlags": 1, "distinctIds": True, "collisionFiles": 2,
                           "collisionDirectoryBatches": 0, "caseRestored": True},
        "subst-drive": {**truths("aliasInitiallyAbsent localNonSystemToken subtreeMappingObserved mappingRemoved"), "rootOpens": 0},
        "unc": {"readerFfiEntries": 0, "readerInstances": 0, "unsafePathRefused": True},
        "device": {"readerFfiEntries": 0, "readerInstances": 0, "unsafePathRefused": True},
        "ads": {"readerFfiEntries": 0, "readerInstances": 0, "unsafePathRefused": True},
        "root-reparse-race": {**race, "preparatoryDeletes": 0},
        "config-reparse-race": {**race, "preparatoryDeletes": 0},
        "walk-reparse-race": {**race, "preparatoryDeletes": 1},
        "case-mode-race": {**truths("parentIdSame originalRelativeEntry entryBeforeDeadline missingNotTrusted caseRestored"),
                           "mutationAccess": 256, "enabledFlags": 1},
        "acl-type": {**truths("fileAccessDenied directoryAccessDenied accessibleSiblingRead configDirectoryRefused"), "daclRestored": 2},
        "read-eof-size": {**truths("emptyEof invalidUtf8Refused shortFinalRead multichunkEof exactLimitEof"),
                          "oversizeReadBytes": 0, "largestRequest": (1, 65536), "largestReturn": (1, 65536)},
        "entry-limit": {"returnedRecords": (10000, 1000000), "chargedEntries": 10000, "overBudgetChildOpens": 0, "entryLimitIssue": True},
        "candidate-limit": {"chargedCandidates": 128, "refusedExtraCandidate": True, "sourceFileLimitIssue": True},
        "aggregate-limit": {"chargedBytes": (0, 8388608), "extraByteRead": 0, "capNotEof": True, "byteLimitIssue": True},
        "depth-path-limit": {"deepestAdmitted": (0, 12), "depth13Opens": 0, "oversizedPathOpens": 0,
                             **truths("depthIssue pathIssue siblingRead")},
        "replace": {**truths("entryObserved originalIdDiffers changedIssue"), "replacementReadBytes": 0},
        "disappear": truths("entryObserved actualMissingReturn changedIssue missingNotTrusted"),
        "config-disappear": truths("entryObserved actualMissingReturn changedIssue missingNotTrusted"),
        "ending-metadata-case": truths("genuineFileEof writeMetadataChanged fileChangeVeto genuineDirectoryEof "
                                       "caseFlagsChanged directoryCaseVeto attributesRestored"),
        "drive-map-change": {**truths("aliasInitiallyAbsent localNonSystemToken initialVolumeMapping endingSubtreeMapping "
                                     "changedIssue mappingRemoved"), "laterProjectOpens": 0},
        "oplock-release": truths("grantPending originalReaderEntered breakSignalled completionKnown blockedBeforeRelease "
                                 "holderCloseReturned observerJoined eventCloseReturned originalReaderReturned"),
        "oplock-withhold": {**truths("grantPending originalReaderEntered breakSignalled completionKnown originalProcessStopped"),
                            "readerReturnedBeforeStop": False, "holderReleasedBeforeStop": False},
        "pending-failstop": {"originalParentHeld": True, "realFsctlEntry": True, "afterCallMarker": False, "originalExitCode": 70},
    }[name]
    checks = closed_object(value, set(expected), "Windows case-check fields differ")
    for field, rule in expected.items():
        actual = checks[field]
        require(integer_between(actual, *rule) if type(rule) is tuple else type(actual) is type(rule) and actual == rule,
                "A required Windows native predicate is not established")


def validate_windows_result(name: str, value: object) -> str | None:
    result = closed_object(value, {"return", "code", "configState", "partial", "scan", "issueCodes", "dtoSha256"},
                           "Windows result fields differ")
    errors = {
        "closed-gate": {"platform_unavailable"}, "reparse-root": {"unsafe_path", "snapshot_unavailable"},
        "reparse-ancestor": {"unsafe_path", "snapshot_unavailable"},
        "root-reparse-race": {"unsafe_path", "snapshot_unavailable"},
        "short-alias": {"unsafe_path", "snapshot_unavailable"}, "case-alias": {"unsafe_path", "snapshot_unavailable"},
        "subst-drive": {"snapshot_unavailable"}, "unc": {"unsafe_path"}, "device": {"unsafe_path"}, "ads": {"unsafe_path"},
        "oplock-withhold": {"query_timeout"}, "pending-failstop": {"engine_failed"},
    }
    if name in errors:
        require(result["return"] == "error" and type(result["code"]) is str and result["code"] in errors[name]
                and all(result[field] is None for field in ("configState", "partial", "scan", "dtoSha256"))
                and result["issueCodes"] == [], "Windows required refusal/owner failure differs")
        return result["code"]
    require(result["return"] == "ok" and result["code"] is None and type(result["configState"]) is str
            and result["configState"] in {"missing", "format-valid", "invalid", "unavailable"}
            and type(result["partial"]) is bool and sha256_value(result["dtoSha256"]), "Windows snapshot result differs")
    scan = closed_object(result["scan"], {"entries", "sourceFiles", "sourceBytes", "excludedEntries"}, "Windows scan fields differ")
    for field, limit in (("entries", 10000), ("sourceFiles", 128), ("sourceBytes", 8388608), ("excludedEntries", 10000)):
        require(integer_between(scan[field], 0, limit), "Windows snapshot scan bound differs")
    codes = result["issueCodes"]
    require(type(codes) is list and len(codes) <= 64
            and all(type(code) is str and code in WINDOWS_SNAPSHOT_ISSUES for code in codes), "Windows issue-code vocabulary differs")
    if name in {"ordinary-source", "ordinary-zip"}:
        require(result["configState"] == "format-valid" and result["partial"] is False and not codes,
                "Ordinary Windows snapshot was not complete")
    elif name != "oplock-release":
        require(result["partial"] is True and bool(codes), "A changed/excluded Windows input was reported as complete")
    if name in {"config-reparse-race", "case-mode-race", "acl-type", "config-disappear", "drive-map-change"}:
        require(result["configState"] == "unavailable", "Unavailable configuration was treated as trustworthy")
    required_codes = {
        "entry-limit": {"snapshot.entry-limit"}, "candidate-limit": {"snapshot.file-limit"},
        "aggregate-limit": {"snapshot.byte-limit"}, "depth-path-limit": {"snapshot.depth-limit", "snapshot.path-limit"},
        "replace": {"snapshot.changed"}, "disappear": {"snapshot.changed"}, "config-disappear": {"snapshot.changed"},
        "ending-metadata-case": {"snapshot.changed"}, "drive-map-change": {"snapshot.changed"},
        "read-eof-size": {"snapshot.encoding", "snapshot.file-size"},
    }.get(name, set())
    require(required_codes <= set(codes), "Windows result does not contain the control's actual required issue")
    return None


def validate_windows_original(name: str, value: object, error: str | None) -> None:
    original = closed_object(value, {"id", *WINDOWS_ORIGINAL_FLAGS, "waitExitCode", "exitSuccess", "stdoutBytes",
                                    "stderrBytes", "unknownLatched", "disabled", "errorCode"},
                             "Windows original-owner fields differ")
    require(original["id"] == "query-1" and all(original[field] is True for field in WINDOWS_ORIGINAL_FLAGS)
            and original["unknownLatched"] is False and original["disabled"] is False
            and original["errorCode"] == error, "Windows original ownership or sticky outcome is incomplete")
    abnormal = name in {"oplock-withhold", "pending-failstop"}
    require(type(original["exitSuccess"]) is bool and original["exitSuccess"] is not abnormal
            and integer_between(original["waitExitCode"], -(2**31), 2**32 - 1)
            and (original["waitExitCode"] != 0 if abnormal else original["waitExitCode"] == 0),
            "Windows original process status differs")
    if name == "pending-failstop":
        require(original["waitExitCode"] == 70, "Windows pending classifier did not return its fixed process status")
    require(integer_between(original["stdoutBytes"], 0 if abnormal else 1, 4 * 1024 * 1024)
            and integer_between(original["stderrBytes"], 0, 64 * 1024), "Windows original stream observations exceed bounds")


def validate_windows_reader(name: str, value: object) -> None:
    reader = closed_object(value, {"state", "calls", *WINDOWS_READER_COUNTERS, "eventSha256", "closeDisposition"},
                           "Windows reader fields differ")
    if name == "closed-gate":
        require(reader["state"] == reader["closeDisposition"] == "uninstrumented" and reader["calls"] == []
                and all(reader[field] is None for field in (*WINDOWS_READER_COUNTERS, "eventSha256")),
                "Uninstrumented Windows refusal invented native observations")
        return
    abnormal = name in {"oplock-withhold", "pending-failstop"}
    require(reader["state"] == ("prefix" if abnormal else "complete")
            and reader["closeDisposition"] == ("not-observed-after-abnormal-exit" if abnormal else "returned-once")
            and sha256_value(reader["eventSha256"]), "Windows reader observation scope differs")
    for field in WINDOWS_READER_COUNTERS:
        maximum = {"maxLive": 144, "live": 144, "maxBufferBytes": 65536, "readBytes": 8388608}.get(field, 1000000)
        require(integer_between(reader[field], 0, maximum), "Windows reader counter exceeds its bound")
    calls = reader["calls"]
    require(type(calls) is list and len(calls) == len(WINDOWS_READER_APIS), "Windows reader API roster differs")
    for call, api in zip(calls, WINDOWS_READER_APIS, strict=True):
        call = closed_object(call, {"api", "entered", "returned", "completed", "errors"}, "Windows reader API fields differ")
        require(call["api"] == api and all(integer_between(call[field], 0, 1000000)
                for field in ("entered", "returned", "completed", "errors")), "Windows reader API counter differs")
        require(call["errors"] <= call["completed"] <= call["returned"] <= call["entered"], "Windows call classification order differs")
        if not abnormal:
            require(call["entered"] == call["returned"] == call["completed"], "Windows entered call is not classified")
    require(reader["outsideReads"] == reader["outsideDescent"] == reader["violations"] == 0,
            "Windows reader crossed an excluded input boundary")
    require(reader["outsideAcquired"] == reader["aliasMetadataAcquired"]
            and (name == "link-children" or reader["outsideAcquired"] == 0), "Windows outside referent was acquired")
    by_api = {call["api"]: call for call in calls}
    opens, closes = by_api["NtCreateFile"], by_api["CloseHandle"]
    reads, information = by_api["ReadFile"], by_api["GetFileInformationByHandleEx"]
    require(reader["rootOpens"] + reader["relativeOpens"] == opens["entered"]
            and reader["acquired"] == opens["completed"] - opens["errors"]
            and reader["closeAttempts"] == closes["entered"]
            and reader["closeSucceeded"] == closes["completed"] - closes["errors"]
            and reader["closeFailed"] == closes["errors"] == 0
            and reader["closeSucceeded"] == reader["closeAttempts"] <= reader["acquired"]
            and reader["live"] == reader["acquired"] - reader["closeAttempts"]
            and reader["live"] <= reader["maxLive"] <= reader["acquired"],
            "Windows reader original-open/close accounting is inconsistent")
    require(reader["identitiesMatched"] == reader["metadataChecks"] <= by_api["GetFileType"]["completed"]
            and 4 * reader["metadataChecks"] + reader["directoryEof"] <= information["completed"]
            and reader["readEof"] <= reads["completed"] - reads["errors"] <= reads["entered"] <= reader["readCalls"]
            and reader["readBytes"] <= 65536 * (reads["completed"] - reads["errors"] - reader["readEof"])
            and reader["directoryEof"] <= reader["directoryCalls"]
            and reader["directoryEof"] <= information["errors"]
            and reader["eventCount"] >= sum(call["completed"] for call in calls),
            "Windows reader identity/read/EOF observations contradict original calls")
    if reader["acquired"]:
        require(reader["maxLive"] > 0 and reader["eventCount"] > 0, "Windows reader acquisition has no resource observations")
    if reader["readCalls"] or reader["directoryCalls"] or reader["metadataChecks"]:
        require(reader["acquired"] > 0 and reader["maxBufferBytes"] > 0,
                "Windows reader IO has no acquired original or output arena")
    if not abnormal:
        require(reader["acquired"] == reader["closeAttempts"] == reader["closeSucceeded"]
                and reader["closeFailed"] == reader["live"] == 0, "Windows reader original closes are incomplete")
    if name in {"ordinary-source", "ordinary-zip", "oplock-release"}:
        require(reader["rootOpens"] == 1 and reader["relativeOpens"] > 0 and reader["metadataChecks"] > 0
                and reader["identitiesMatched"] > 0 and reader["readEof"] > 0 and reader["directoryEof"] > 0,
                "Ordinary Windows handles, identity or EOF were not observed")
    if name in {"unc", "device", "ads"}:
        require(all(call["entered"] == 0 for call in calls) and reader["acquired"] == 0,
                "Unsafe Windows namespace reached the reader API")
    else:
        require(by_api["GetCurrentProcess"]["completed"] == by_api["IsWow64Process2"]["completed"] == 1
                and by_api["QueryDosDeviceW"]["completed"] > 0, "Windows reader native admission was not observed")
    if abnormal:
        pending_api = "NtCreateFile" if name == "oplock-withhold" else "DeviceIoControl"
        require(reader["rootOpens"] == 1 and reader["relativeOpens"] > 0 and reader["live"] > 0
                and reader["identitiesMatched"] > 0
                and all(call["entered"] - call["returned"] == (1 if call["api"] == pending_api else 0)
                        and call["returned"] == call["completed"] for call in calls),
                "Windows abnormal prefix lacks its retained parent or exact unmatched native entry")


def validate_windows_fixture(name: str, value: object, bindings: dict) -> None:
    fixture = closed_object(value, {"state", *WINDOWS_FIXTURE_COUNTERS, "pending", "thread", "event", "restored",
                                   "resourcesSettledBy", "data", "profile", "checks"}, "Windows fixture fields differ")
    validate_windows_checks(name, fixture["checks"])
    if name == "closed-gate":
        require(fixture["state"] == fixture["resourcesSettledBy"] == "uninstrumented"
                and all(fixture[field] is None for field in (*WINDOWS_FIXTURE_COUNTERS, "restored", "data", "profile"))
                and all(fixture[field] == "none" for field in ("pending", "thread", "event")),
                "Uninstrumented Windows refusal invented fixture observations")
        return
    abnormal = name in {"oplock-withhold", "pending-failstop"}
    require(fixture["state"] == ("prefix" if abnormal else "complete")
            and fixture["resourcesSettledBy"] == ("original-process" if abnormal else "returned-closes"),
            "Windows fixture settlement class differs")
    for field in WINDOWS_FIXTURE_COUNTERS:
        require(integer_between(fixture[field], 0, {"live": 32, "maxLive": 32, "maxArenaBytes": 131072}.get(field, 1000000)),
                "Windows fixture counter exceeds its bound")
    require(fixture["closeSucceeded"] == fixture["closeAttempts"] <= fixture["acquired"]
            and fixture["closeFailed"] == 0 and fixture["live"] == fixture["acquired"] - fixture["closeAttempts"]
            and fixture["live"] <= fixture["maxLive"] <= fixture["acquired"]
            and fixture["maxLive"] > 0 and fixture["maxArenaBytes"] > 0, "Windows fixture accounting is inconsistent")
    if abnormal:
        require(fixture["restored"] is None and fixture["event"] == "retained"
                and fixture["pending"] == ("completed" if name == "oplock-withhold" else "retained")
                and fixture["thread"] == ("not-observed" if name == "oplock-withhold" else "none"),
                "Abnormal Windows exit invented in-process cleanup")
        require(fixture["live"] >= 2 and fixture["maxLive"] >= 2 and fixture["maxArenaBytes"] >= 36,
                "Windows pending prefix lacks its retained holder/event/OVERLAPPED resources")
    else:
        require(fixture["restored"] is True and fixture["acquired"] == fixture["closeAttempts"] == fixture["closeSucceeded"]
                and fixture["live"] == fixture["closeFailed"] == 0, "Windows fixture restoration/closes are incomplete")
        require((fixture["pending"], fixture["thread"], fixture["event"])
                == (("completed", "joined", "closed") if name == "oplock-release" else ("none", "none", "none")),
                "Windows pending IO or thread/event settlement differs")
        if name == "oplock-release":
            require(fixture["acquired"] >= 2 and fixture["maxLive"] >= 2 and fixture["maxArenaBytes"] >= 36,
                    "Windows released oplock lacks its original resource observations")
    data = closed_object(fixture["data"], {"entries", "bytes", "maxDepth", "manifestSha256", "after"}, "Windows fixture data fields differ")
    require(integer_between(data["entries"], 3, 12000) and integer_between(data["bytes"], 0, 32 * 1024 * 1024)
            and integer_between(data["maxDepth"], 0, 14) and sha256_value(data["manifestSha256"]), "Windows fixture data exceeds its bound")
    after = closed_object(data["after"], {"entries", "bytes", "maxDepth", "inventorySha256"}, "Windows final payload inventory is missing")
    require(integer_between(after["entries"], 3, 12000) and integer_between(after["bytes"], 0, 32 * 1024 * 1024)
            and integer_between(after["maxDepth"], 0, 14) and sha256_value(after["inventorySha256"]),
            "Windows actual post-settlement payload exceeds its bound")
    profile = closed_object(fixture["profile"], {"pointerBytes", "processMachine", "nativeMachine", "filesystem",
                                              "pythonSha256", "ctypesSha256", "dlls", "layoutSha256", "sdkSha256"},
                            "Windows native profile fields differ")
    require(type(profile["pointerBytes"]) is int and profile["pointerBytes"] == 8
            and type(profile["processMachine"]) is int and profile["processMachine"] == 0
            and type(profile["nativeMachine"]) is int and profile["nativeMachine"] == 34404
            and profile["filesystem"] == "NTFS" and profile["pythonSha256"] == bindings["pythonSha256"]
            and all(sha256_value(profile[field]) for field in ("ctypesSha256", "layoutSha256", "sdkSha256"))
            and profile["sdkSha256"] == hashlib.sha256(canonical_json(bindings["sdk"])).hexdigest(),
            "Windows native architecture/SDK profile differs")
    dlls = profile["dlls"]
    require(type(dlls) is list and len(dlls) == 3, "Windows selected DLL roster differs")
    for dll, expected in zip(dlls, ("kernel32.dll", "ntdll.dll", "advapi32.dll"), strict=True):
        dll = closed_object(dll, {"name", "sha256", "size"}, "Windows selected DLL fields differ")
        require(dll["name"] == expected and sha256_value(dll["sha256"]) and integer_between(dll["size"], 1, 64 * 1024 * 1024),
                "Windows selected DLL identity differs")


def validate_windows_snapshot_receipt(receipt: object, *, bindings: dict) -> dict:
    report = closed_object(receipt, {"schemaVersion", "scope", "status", "failureCode", "bindings", "groups",
                                    "allOwnersSettled", "allFixtureResourcesSettled", "allFixturesRestored",
                                    "cleanupDisposition", "notVerified"}, "Windows receipt fields differ")
    require(type(report["schemaVersion"]) is int and report["schemaVersion"] == 1
            and report["scope"] == WINDOWS_SNAPSHOT_RECEIPT_SCOPE and report["status"] == "passed"
            and report["failureCode"] is None and report["cleanupDisposition"] == "proven-settled"
            and all(report[field] is True for field in ("allOwnersSettled", "allFixtureResourcesSettled", "allFixturesRestored"))
            and report["notVerified"] == list(WINDOWS_SNAPSHOT_NOT_VERIFIED), "Windows receipt is not a complete bounded pass")
    # Byte equality of closed canonical data also distinguishes bool from int.
    require(canonical_json(report["bindings"]) == canonical_json(bindings), "Windows receipt source/run/profile bindings differ")
    groups = report["groups"]
    require(type(groups) is list and len(groups) == len(WINDOWS_SNAPSHOT_GROUPS), "Windows native group roster is incomplete")
    for group, (expected_group, names) in zip(groups, WINDOWS_SNAPSHOT_GROUPS, strict=True):
        group = closed_object(group, {"id", "controls"}, "Windows native group fields differ")
        require(group["id"] == expected_group and type(group["controls"]) is list and len(group["controls"]) == len(names),
                "Windows native controls are missing, reordered or duplicated")
        for control, name in zip(group["controls"], names, strict=True):
            control = closed_object(control, {"id", "coreMode", "bootstrapMode", "evidenceKind", "result", "reader", "fixture",
                                              "original", "elapsedMs", "failureCode"}, "Windows native control fields differ")
            evidence = {"closed-gate": "uninstrumented-public-refusal", "oplock-withhold": "original-process-oplock-stop",
                        "pending-failstop": "instrumented-pending-classifier-exit"}.get(name, "native-static-reader")
            require(control["id"] == name and control["coreMode"] == ("zip" if name == "ordinary-zip" else "source")
                    and control["bootstrapMode"] == ("ordinary" if name == "closed-gate" else "windows-snapshot")
                    and control["evidenceKind"] == evidence and control["failureCode"] is None
                    and integer_between(control["elapsedMs"], 0, 45000), "Windows native control scope differs")
            error = validate_windows_result(name, control["result"])
            validate_windows_original(name, control["original"], error)
            validate_windows_reader(name, control["reader"])
            validate_windows_fixture(name, control["fixture"], bindings)
            charged = {"entry-limit": ("entries", "chargedEntries"), "candidate-limit": ("sourceFiles", "chargedCandidates"),
                       "aggregate-limit": ("sourceBytes", "chargedBytes")}.get(name)
            if charged:
                require(control["result"]["scan"][charged[0]] == control["fixture"]["checks"][charged[1]],
                        "Windows native charged count and genuine snapshot scan differ")
    return report


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
                  scope: str = "passive-development-foundation-only", compiled: dict | None = None) -> None:
    # Only called after the fixed phase and final source check actually succeed.
    # Missing files on failed/skipped phases cannot become passing evidence.
    receipt = {
        "schemaVersion": 1, "scope": scope, "phase": name,
        "status": "passed", "sourceSha": context["sourceSha"], "platform": context["platform"],
        "rust": {"release": RUST, "target": TARGETS[context["platform"]]}, "node": node,
        "checks": [{"check": check, "exitCode": 0} for check in checks],
    }
    if compiled is not None:
        require(context["scope"] == WINDOWS_SNAPSHOT_SCOPE and name == "compile", "Unexpected compiler artifact receipt")
        receipt["compiledTest"] = {"sha256": compiled["sha256"], "size": compiled["size"],
                                   "invocationSha256": compiled["invocationSha256"]}
    write_json(Path(context["root"]) / f"{name}-checks.json", receipt)


def prepare(platform: str) -> None:
    scope = admitted_scope(platform)
    windows = scope == WINDOWS_SNAPSHOT_SCOPE
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
    directories = (("home", "cargo", "rustup", "tmp", "target", "windows-snapshot", "appdata", "localappdata") if windows else
                   ("home", "cargo", "rustup", "tmp", "target", "native", "config-owner", "config-driver-loss", "config-watchdog-loss",
                    "config-stop", "config-terminal-deadline", "config-startup-stop", "config-transaction-eof",
                    "appdata", "localappdata", "npm-cache"))
    for name in directories:
        (root / name).mkdir(mode=0o700)
    for name in (("gitconfig-empty",) if windows else ("npmrc-user", "npmrc-global", "gitconfig-empty")):
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
    context = {"root": str(root), "source": str(source), "sourceSha": sha, "sourceTree": tree, "platform": platform, "scope": scope,
               "event": os.environ["GITHUB_EVENT_NAME"], "ref": os.environ["GITHUB_REF"],
               "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
               "git": git, "rustup": rustup, "python": str(Path(sys.executable).resolve(strict=True))}
    source_unchanged(context)
    public = {
        "scope": WINDOWS_SNAPSHOT_PUBLIC_SCOPE if windows else "passive-development-foundation-only",
        "sourceSha": sha, "sourceTree": tree,
        "workflowSha256": hash_file(source / ".github/workflows/desktop-foundation.yml"),
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
    if windows:
        windows_prepare_bindings(context, public)
    write_json(root / "context.json", context)
    write_json(root / "public-bindings.json", public)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8", newline="\n") as output:
        output.write(f"root={root}\n")
    print("Prepared bounded source ZIP and source-bound synthetic check inputs.")


def load_context(platform: str) -> dict:
    scope = admitted_scope(platform)
    root = Path(os.environ["MRK_DESKTOP_CI_ROOT"])
    require(root.is_absolute() and root.name.startswith("mrk-desktop-foundation-")
            and root.parent == Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
            and not root.is_symlink(), "Unrecognized task root")
    ordinary(root / "context.json")
    context = json.loads((root / "context.json").read_text(encoding="utf-8"))
    require(context["root"] == str(root) and context["platform"] == platform and context["scope"] == scope
            and context["event"] == os.environ["GITHUB_EVENT_NAME"] and context["ref"] == os.environ["GITHUB_REF"]
            and context["sourceSha"] == os.environ["GITHUB_SHA"]
            and context["runId"] == os.environ["GITHUB_RUN_ID"]
            and context["attempt"] == os.environ["GITHUB_RUN_ATTEMPT"], "Task context differs")
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


def phase(name: str, platform: str) -> None:
    context = load_context(platform)
    windows = context["scope"] == WINDOWS_SNAPSHOT_SCOPE
    require((name in WINDOWS_SNAPSHOT_PHASES) if windows else name != "windows-snapshot",
            "Phase is not part of this fixed verification scope")
    root, source = Path(context["root"]), Path(context["source"])
    environment = clean_environment(root)
    # The owner fixture binds its compiled source to this exact event commit.
    # Compile and test must use the same value; no None/ambient/latest fallback.
    environment["GITHUB_SHA"] = context["sourceSha"]
    manifest = source / "desktop/src-tauri/Cargo.toml"
    source_unchanged(context)
    no_cargo_configuration((root, *root.parents))
    if name == "acquire":
        run([context["rustup"], "toolchain", "install", RUST, "--profile", "minimal", "--no-self-update"],
            check="rust-toolchain-install", cwd=root, env=environment, timeout=600)
        cargo, _ = tools(context, environment)
        features = "development-runtime" if windows else "desktop-shell,development-runtime"
        # Metadata filters acquisition to this platform and active feature graph.
        with (root / "metadata.json").open("x", encoding="utf-8") as output:
            run([cargo, "metadata", "--locked", "--format-version", "1", "--no-default-features",
                 "--features", features, "--filter-platform", TARGETS[platform],
                 "--manifest-path", str(manifest)], check="locked-platform-metadata", cwd=root,
                env=environment, timeout=600, output=output)
        if windows:
            source_unchanged(context)
            phase_receipt(context, name, ["rust-toolchain-install", "rust-version-target", "locked-platform-metadata"],
                          scope=WINDOWS_SNAPSHOT_PUBLIC_SCOPE)
            return
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
        argv = [cargo, "test", *common, "--lib", "--no-run", "--features", "development-runtime"]
        if windows:
            argv.append("--message-format=json")
            messages = root / "windows-compile-messages.jsonl"
            with messages.open("x", encoding="utf-8", newline="\n") as output:
                run(argv, check="headless-test-compile-only", cwd=root, env=environment, timeout=600, output=output)
            compiled = windows_compile_record(context, argv, messages)
            source_unchanged(context)
            phase_receipt(context, name, ["rust-version-target", "headless-test-compile-only"],
                          scope=WINDOWS_SNAPSHOT_PUBLIC_SCOPE, compiled=compiled)
            return
        run(argv, check="headless-test-compile-only", cwd=root, env=environment, timeout=600)
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
    elif name == "windows-snapshot":
        require(windows and platform == "windows", "Windows snapshot phase requires its dedicated scope")
        windows_inputs(context, create=True)
        environment.update(MRK_DESKTOP_DEV_PYTHON=context["python"], MRK_DESKTOP_DEV_CORE=str(source / "src"),
                           MRK_DESKTOP_TEST_ROOT=str(root / "windows-snapshot"), MRK_DESKTOP_TEST_CORE_ZIP=str(root / "core.zip"),
                           MRK_DESKTOP_HOSTED_CHECKS=WINDOWS_SNAPSHOT_SCOPE, GITHUB_ACTIONS="true",
                           RUNNER_ENVIRONMENT="github-hosted", GITHUB_SHA=context["sourceSha"])
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", WINDOWS_SNAPSHOT_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="windows-snapshot-native-contract",
            cwd=root, env=environment, timeout=300)
        source_unchanged(context)
        windows_snapshot_receipt(context)
        phase_receipt(context, name, ["rust-version-target", WINDOWS_SNAPSHOT_TEST, "windows-snapshot-original-resource-receipt-acceptance"],
                      scope=WINDOWS_SNAPSHOT_PUBLIC_SCOPE)
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
        if windows:
            clean_windows_outputs(context)
            return
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
    parser.add_argument("phase", choices=("prepare", "acquire", "compile", "native", "config-owner", "config-task-loss", "config-owner-delta", "config-transaction-eof", "config-core", "windows-snapshot", "clean"))
    args = parser.parse_args()
    os.umask(0o077)
    print(f"Starting fixed desktop phase: {args.phase}", flush=True)
    try:
        platform = admitted_host()
        prepare(platform) if args.phase == "prepare" else phase(args.phase, platform)
    except Exception as error:
        reason = str(error) if isinstance(error, CheckFailure) else type(error).__name__
        print(f"Desktop {args.phase} failed: {reason}. Preserve evidence; no native or product success is implied.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
