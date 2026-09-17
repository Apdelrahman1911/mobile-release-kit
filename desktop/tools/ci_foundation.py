"""Fixed desktop compiler/passive-IPC checks on disposable hosted runners only.

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
import zipfile

RUST = "1.98.0"
PYTHON = "3.14.7"
NODE = "v24.20.0"
NATIVE_TEST = "supervisor::hosted_tests::passive_hosted_contract"
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
)


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


def run(argv: list[str], *, cwd: Path, env: dict[str, str], timeout: int,
        capture: bool = False) -> str:
    # Only fixed commands below reach this internal helper. No shell, inherited
    # credentials, renderer input, project hook or arbitrary command selection.
    result = subprocess.run(argv, cwd=cwd, env=env, check=True, timeout=timeout,
                            text=True, stdout=subprocess.PIPE if capture else None)
    if capture:
        require(len(result.stdout.encode("utf-8")) <= 1024 * 1024, "Tool metadata exceeded its bound")
        return result.stdout.strip()
    return ""


def admitted_host() -> str:
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("MRK_DESKTOP_HOSTED_CHECKS") == "passive-v1",
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
    require(run([git, "rev-parse", "HEAD"], cwd=source, env=environment, timeout=15, capture=True)
            == context["sourceSha"], "Checkout commit changed")
    run([git, "diff", "--no-ext-diff", "--no-textconv", "--exit-code", "--quiet", "HEAD", "--"],
        cwd=source, env=environment, timeout=15)


def no_cargo_configuration(directories: tuple[Path, ...]) -> None:
    for directory in directories:
        for name in ("config", "config.toml"):
            path = directory / ".cargo" / name
            require(not path.exists() and not path.is_symlink(), "Ambient Cargo configuration is not admitted")


def native_receipt(context: dict) -> dict:
    path = Path(context["root"]) / "native/receipt.json"
    ordinary(path)
    size = path.stat().st_size
    require(0 < size <= 64 * 1024, "Native receipt size differs")
    with path.open("rb") as stream:
        data = stream.read(size + 1)
    require(len(data) == size, "Native receipt changed")
    receipt = json.loads(data)
    require(receipt.get("schemaVersion") == 1 and receipt.get("scope") == "passive-hosted-v1"
            and receipt.get("status") == "passed" and receipt.get("allOwnersSettled") is True,
            "Native ownership is not confirmed settled; preserve outputs")
    bindings = receipt.get("bindings", {})
    require(bindings.get("sourceSha") == context["sourceSha"]
            and bindings.get("target") == TARGETS[context["platform"]]
            and bindings.get("coreZipSha256") == hash_file(Path(context["root"]) / "core.zip"),
            "Native receipt source/target differs")
    cases = receipt.get("cases", [])
    require(isinstance(cases, list) and tuple(case.get("case") for case in cases) == NATIVE_CASES
            and all(case.get("passed") is True for case in cases), "Fixed native batch was not fully verified")
    return receipt


def phase_receipt(context: dict, name: str, checks: list[str], *, node: str | None = None) -> None:
    # Only called after the fixed phase and final source check actually succeed.
    # Missing files on failed/skipped phases cannot become passing evidence.
    write_json(Path(context["root"]) / f"{name}-checks.json", {
        "schemaVersion": 1, "scope": "passive-development-foundation-only", "phase": name,
        "status": "passed", "sourceSha": context["sourceSha"], "platform": context["platform"],
        "rust": {"release": RUST, "target": TARGETS[context["platform"]]}, "node": node,
        "checks": [{"check": check, "exitCode": 0} for check in checks],
    })


def prepare(platform: str) -> None:
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
    for name in ("home", "cargo", "rustup", "tmp", "target", "native", "appdata", "localappdata", "npm-cache"):
        (root / name).mkdir(mode=0o700)
    for name in ("npmrc-user", "npmrc-global", "gitconfig-empty"):
        (root / name).touch(mode=0o600, exist_ok=False)
    git = shutil.which("git")
    rustup = shutil.which("rustup")
    require(git is not None and rustup is not None, "Hosted compiler tools unavailable")
    environment = clean_environment(root)
    require(run([git, "rev-parse", "HEAD"], cwd=source, env=environment, timeout=15, capture=True) == sha,
            "Event and checkout source differ")
    tree = run([git, "rev-parse", "HEAD^{tree}"], cwd=source, env=environment, timeout=15, capture=True)
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
               "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
               "git": git, "rustup": rustup, "python": str(Path(sys.executable).resolve(strict=True))}
    source_unchanged(context)
    write_json(root / "context.json", context)
    write_json(root / "public-bindings.json", {
        "scope": "passive-development-foundation-only", "sourceSha": sha, "sourceTree": tree,
        "workflowSha256": hash_file(source / ".github/workflows/desktop-foundation.yml"),
        "runId": context["runId"], "attempt": context["attempt"], "platform": platform,
        "image": os.environ.get("ImageOS", "") + "/" + os.environ.get("ImageVersion", ""),
        "architecture": os.environ["RUNNER_ARCH"], "python": PYTHON, "expectedRust": RUST,
        "coreZipSha256": hash_file(root / "core.zip"), "coreFiles": inventory,
        "bootstrapSha256": hash_file(source / "desktop/engine_bootstrap.py"),
        "cargoLockSha256": hash_file(source / "desktop/src-tauri/Cargo.lock"),
        "npmLockSha256": hash_file(source / "desktop/package-lock.json"),
        "notQualified": ["production-runtime", "native-GUI", "Windows-filesystem", "installers", "release-operations"],
    })
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8", newline="\n") as output:
        output.write(f"root={root}\n")
    print("Prepared bounded source ZIP and source-bound synthetic check inputs.")


def load_context(platform: str) -> dict:
    root = Path(os.environ["MRK_DESKTOP_CI_ROOT"])
    require(root.is_absolute() and root.name.startswith("mrk-desktop-foundation-")
            and root.parent == Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
            and not root.is_symlink(), "Unrecognized task root")
    ordinary(root / "context.json")
    context = json.loads((root / "context.json").read_text(encoding="utf-8"))
    require(context["root"] == str(root) and context["platform"] == platform
            and context["sourceSha"] == os.environ["GITHUB_SHA"]
            and context["runId"] == os.environ["GITHUB_RUN_ID"]
            and context["attempt"] == os.environ["GITHUB_RUN_ATTEMPT"], "Task context differs")
    return context


def tools(context: dict, environment: dict[str, str]) -> tuple[str, str]:
    root = Path(context["root"])
    cargo = run([context["rustup"], "which", "--toolchain", RUST, "cargo"], cwd=root,
                env=environment, timeout=15, capture=True)
    rustc = run([context["rustup"], "which", "--toolchain", RUST, "rustc"], cwd=root,
                env=environment, timeout=15, capture=True)
    require(all(Path(value).is_absolute() and Path(value).is_file() for value in (cargo, rustc)),
            "Selected compiler paths unavailable")
    version = run([rustc, "-vV"], cwd=root, env=environment, timeout=15, capture=True)
    require(f"release: {RUST}\n" in version + "\n"
            and f"host: {TARGETS[context['platform']]}\n" in version + "\n", "Compiler host/version differs")
    environment["RUSTC"] = rustc
    environment["PATH"] = str(Path(cargo).parent) + os.pathsep + environment["PATH"]
    return cargo, rustc


def phase(name: str, platform: str) -> None:
    context = load_context(platform)
    root, source = Path(context["root"]), Path(context["source"])
    environment = clean_environment(root)
    manifest = source / "desktop/src-tauri/Cargo.toml"
    source_unchanged(context)
    no_cargo_configuration((root, *root.parents))
    if name == "acquire":
        run([context["rustup"], "toolchain", "install", RUST, "--profile", "minimal"],
            cwd=root, env=environment, timeout=600)
        cargo, _ = tools(context, environment)
        features = "development-runtime" if platform == "linux" else "desktop-shell,development-runtime"
        # Metadata filters acquisition to this platform and active feature graph.
        with (root / "metadata.json").open("x", encoding="utf-8") as output:
            subprocess.run([cargo, "metadata", "--locked", "--format-version", "1", "--no-default-features",
                            "--features", features, "--filter-platform", TARGETS[platform],
                            "--manifest-path", str(manifest)], cwd=root, env=environment,
                           check=True, timeout=600, stdout=output, text=True)
        observed_node = None
        if platform != "linux":
            node = shutil.which("node")
            require(node is not None, "Selected Node unavailable")
            observed_node = run([node, "--version"], cwd=root, env=environment, timeout=15, capture=True)
            require(observed_node == NODE, "Selected Node version differs")
            npm = (Path(node).parent / "node_modules/npm/bin/npm-cli.js" if platform == "windows" else
                   Path(node).parent.parent / "lib/node_modules/npm/bin/npm-cli.js")
            ordinary(npm)
            run([node, "--max-old-space-size=768", str(npm), "ci", "--ignore-scripts", "--no-audit", "--no-fund",
                 "--userconfig", str(root / "npmrc-user"), "--globalconfig", str(root / "npmrc-global"),
                 "--cache", str(root / "npm-cache"), "--registry", "https://registry.npmjs.org/"],
                cwd=source / "desktop", env=environment, timeout=300)
        source_unchanged(context)
        phase_receipt(context, name, ["rust-toolchain-install", "rust-version-target", "locked-platform-metadata"]
                      + (["node-version", "npm-locked-no-scripts"] if platform != "linux" else []), node=observed_node)
        return
    cargo, _ = tools(context, environment)
    common = ["--locked", "--offline", "--jobs", "1", "--no-default-features",
              "--target", TARGETS[platform], "--manifest-path", str(manifest), "--target-dir", str(root / "target")]
    if name == "compile":
        run([cargo, "test", *common, "--lib", "--no-run", "--features", "development-runtime"],
            cwd=root, env=environment, timeout=600)
        observed_node = None
        if platform != "linux":
            node = shutil.which("node")
            require(node is not None, "Node unavailable after setup")
            observed_node = run([node, "--version"], cwd=root, env=environment, timeout=15, capture=True)
            require(observed_node == NODE, "Selected Node version changed")
            desktop = source / "desktop"
            run([node, "--max-old-space-size=768", "node_modules/typescript/bin/tsc", "--noEmit", "-p", "tsconfig.json"],
                cwd=desktop, env=environment, timeout=60)
            run([node, "--max-old-space-size=768", "node_modules/vite/bin/vite.js", "build", "--config",
                 str(desktop / "vite.config.mjs"), "--configLoader", "native", "--outDir", str(desktop / "dist")],
                cwd=desktop, env=environment, timeout=90)
            run([cargo, "build", *common, "--features", "desktop-shell,development-runtime",
                 "--bin", "mobile-release-kit-desktop"], cwd=root, env=environment, timeout=1500)
        source_unchanged(context)
        phase_receipt(context, name, ["rust-version-target", "headless-test-compile-only"]
                      + (["node-version", "typescript-no-emit", "vite-assets", "tauri-debug-compile-only"]
                         if platform != "linux" else []), node=observed_node)
    elif name == "native":
        environment.update(MRK_DESKTOP_DEV_PYTHON=context["python"], MRK_DESKTOP_DEV_CORE=str(source / "src"),
                           MRK_DESKTOP_TEST_ROOT=str(root / "native"), MRK_DESKTOP_TEST_CORE_ZIP=str(root / "core.zip"),
                           MRK_DESKTOP_HOSTED_CHECKS="passive-v1", GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                           GITHUB_SHA=context["sourceSha"])
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", NATIVE_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], cwd=root, env=environment, timeout=300)
        source_unchanged(context)
        native_receipt(context)
        phase_receipt(context, name, ["rust-version-target", NATIVE_TEST, "native-receipt-acceptance"])
    else:
        require(name == "clean", "Unknown fixed phase")
        native_receipt(context)
        # Only fresh outputs whose absence prepare() required. No dependency or
        # file outside this exact job root/fresh checkout is selected for removal.
        for relative in ("desktop/node_modules", "desktop/dist", "desktop/src-tauri/gen"):
            output = source / relative
            require(not output.is_symlink(), "Generated output became a link")
            if output.exists():
                shutil.rmtree(output)
        shutil.rmtree(root)
        print("Removed settled task-owned compiler, dependency and fixture outputs.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "acquire", "compile", "native", "clean"))
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
