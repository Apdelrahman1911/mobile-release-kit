set -euo pipefail
"$MRK_PYTHON" -I -S -B - <<'PY_EFFECTIVE_RUST'
import json, os, subprocess, tomllib
from pathlib import Path
checkout = Path(os.environ["GITHUB_WORKSPACE"])
cwd = checkout / "desktop/src-tauri"
root = Path(os.environ["MRK_MACOS_WORK"])
status_name = "observer-build.status" if os.environ["MRK_MACOS_NATIVE_SCOPE"] in ("project-identity-native", "tool-setup", "git-native") else "normal-build.status"
if (root / status_name).read_bytes() != b"0\n":
    raise ValueError("effective versions require the original successful build")
repository_default = tomllib.loads((checkout / "desktop/rust-toolchain.toml").read_text())["toolchain"]["channel"]
selected_toolchain = os.environ.get("RUSTUP_TOOLCHAIN")
build_target = os.environ["MRK_MACOS_TARGET"]
if build_target not in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
    raise ValueError("effective-rust-target")
rust_tuples = {
    "aarch64-apple-darwin": ("1.98.1", "48a229ceaefd4985c50990b14116b6d856af0985"),
    "x86_64-apple-darwin": ("1.98.0", "88d9e12ae178fab0fb5cc050a94da85685d449ea"),
}
rust_release, rust_commit = rust_tuples[build_target]
if repository_default != "1.98.0" or selected_toolchain != rust_release:
    raise ValueError("review the changed repository default or Mac clock toolchain before this gate")
# Query only the same admitted direct tools; no shim or installation.
rust_bin = "/Users/runner/.rustup/toolchains/" + os.environ["RUSTUP_TOOLCHAIN"] + "-" + build_target + "/bin"
environment = dict(os.environ, PATH=rust_bin + ":/usr/bin:/bin:/usr/sbin:/sbin", HOME="/Users/runner", CARGO_HOME="/Users/runner/.cargo", RUSTUP_HOME="/Users/runner/.rustup", RUSTC=rust_bin + "/rustc", RUSTUP_AUTO_INSTALL="0")
versions = {}
for tool in ("rustc", "cargo"):
    command = [rust_bin + "/" + tool, "--version", "--verbose"]
    result = subprocess.run(command, cwd=cwd, env=environment, check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    if result.stderr or not result.stdout or len(result.stdout) > 4096:
        raise ValueError("effective version output refused")
    output = result.stdout.decode("utf-8", "strict").strip()
    lines = output.splitlines()
    if (not output.startswith(tool + " ")
            or [line for line in lines if line.partition(':')[0].strip() == 'release'] != ['release: ' + rust_release]
            or [line for line in lines if line.partition(':')[0].strip() == 'host'] != ['host: ' + build_target]):
        raise ValueError("effective tool version output refused")
    if tool == "rustc" and [line for line in lines if line.partition(':')[0].strip() == 'commit-hash'] != ['commit-hash: ' + rust_commit]:
        raise ValueError("effective compiler differs from reviewed Apple clock binding")
    # Existing schema names the logical role; actual argv above is absolute.
    versions[tool] = {"command": [tool, "--version", "--verbose"], "output": output}
value = {"schemaVersion": 1, "source": os.environ["GITHUB_SHA"],
         "workflowSource": os.environ["GITHUB_WORKFLOW_SHA"],
         "runId": os.environ["GITHUB_RUN_ID"], "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"],
         "cwd": "desktop/src-tauri", "target": build_target, "autoInstall": False, "tools": versions,
         "repositoryDefault": repository_default, "selectedMacToolchain": selected_toolchain}
fd = os.open(root / "effective-rust-toolchain.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
try:
    with os.fdopen(fd, "wb", closefd=False) as stream:
        stream.write((json.dumps(value, sort_keys=True) + "\n").encode()); stream.flush(); os.fsync(fd)
finally: os.close(fd)
PY_EFFECTIVE_RUST
