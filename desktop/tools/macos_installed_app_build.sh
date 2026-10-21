set -euo pipefail
cd desktop
npm ci --ignore-scripts --no-audit --no-fund --cache "$MRK_MACOS_WORK/npm-cache"
npm run build
cd src-tauri
set -o noclobber
if [[ "$MRK_MACOS_NATIVE_SCOPE" == project-identity-native || "$MRK_MACOS_NATIVE_SCOPE" == tool-setup || "$MRK_MACOS_NATIVE_SCOPE" == git-native ]]; then
# Same fixed observer target and original Cargo artifact checks;
# no ordinary cdylib, fallback executable or test execution. Render
# diagnostics to stderr, not repeated warning payloads in the artifact JSON.
set +e
PATH="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin:/usr/bin:/bin:/usr/sbin:/sbin" RUSTC="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin/rustc" RUSTUP_TOOLCHAIN="$RUSTUP_TOOLCHAIN" RUSTUP_AUTO_INSTALL=0 CARGO_HOME=/Users/runner/.cargo RUSTUP_HOME=/Users/runner/.rustup "/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin/cargo" test --locked --no-default-features --features desktop-shell,custom-protocol,macos-installed-observation \
  --target "$MRK_MACOS_TARGET" --test installed-shell-observation --no-run --message-format=json-render-diagnostics \
  > "$MRK_MACOS_WORK/observer-build.jsonl" 2> "$MRK_MACOS_WORK/observer-build.stderr"
status=$?
set -e
printf '%s\n' "$status" > "$MRK_MACOS_WORK/observer-build.status"
if [[ "$status" != 0 ]]; then
  printf 'Observer compiler failed with original status %s; bounded diagnostics are retained.\n' "$status" >&2
  exit "$status"
fi
"$MRK_PYTHON" -I -S -B - <<'PY_BUILD'
import hashlib, json, os, pathlib, re, stat
root = pathlib.Path(os.environ["MRK_MACOS_WORK"])
path = root / "observer-build.jsonl"
if path.stat().st_size > 4 * 1024 * 1024: raise ValueError(f"compiler record bound ({path.stat().st_size} bytes)")
rows = [json.loads(line) for line in path.read_bytes().splitlines()]
if [r.get("success") for r in rows if r.get("reason") == "build-finished"] != [True]: raise ValueError("original compiler did not finish")
targets = [r for r in rows if r.get("reason") == "compiler-artifact" and r.get("target", {}).get("name") == "installed-shell-observation" and r["target"].get("kind") == ["test"] and r.get("executable")]
if len(targets) != 1 or targets[0].get("profile", {}).get("test") is not True: raise ValueError("one actual-main test target required")
binary = pathlib.Path(targets[0]["executable"])
expected = pathlib.Path(os.environ["CARGO_TARGET_DIR"]) / os.environ["MRK_MACOS_TARGET"] / "debug/deps"
if binary.parent != expected or not re.fullmatch(r"installed_shell_observation-[0-9a-f]+", binary.name): raise ValueError("fixed observation target path")
m = binary.lstat()
if not stat.S_ISREG(m.st_mode) or m.st_nlink != 1 or m.st_mode & 0o111 == 0: raise ValueError("original compiler artifact type")
identity = lambda s: (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
try:
    before = os.fstat(fd)
    if identity(before) != identity(m) or not 0 < before.st_size <= 512 * 1024 * 1024:
        raise ValueError("original observer artifact changed or oversized")
    h = hashlib.sha256()
    for offset in range(0, before.st_size, 65536):
        block = os.read(fd, min(65536, before.st_size - offset))
        if len(block) != min(65536, before.st_size - offset): raise ValueError("short original artifact read")
        h.update(block)
    if (os.read(fd, 1) or identity(before) != identity(os.fstat(fd))
            or identity(before) != identity(os.stat(binary, follow_symlinks=False))):
        raise ValueError("original observer artifact changed")
finally: os.close(fd)
with open(os.environ["GITHUB_ENV"], "a") as stream:
    stream.write("MRK_MACOS_OBSERVER_BINARY=" + str(binary) + "\n")
    stream.write("MRK_MACOS_OBSERVER_SHA256=" + h.hexdigest() + "\n")
PY_BUILD
else
set +e
PATH="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin:/usr/bin:/bin:/usr/sbin:/sbin" RUSTC="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin/rustc" RUSTUP_TOOLCHAIN="$RUSTUP_TOOLCHAIN" RUSTUP_AUTO_INSTALL=0 CARGO_HOME=/Users/runner/.cargo RUSTUP_HOME=/Users/runner/.rustup "/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin/cargo" build --locked --release --manifest-path ../helpers/macos-desktop-image/Cargo.toml --lib \
  --target "$MRK_MACOS_TARGET" --message-format=json-render-diagnostics \
  > "$MRK_MACOS_WORK/normal-build.jsonl" 2> "$MRK_MACOS_WORK/normal-build.stderr"
cargo_status=$?
set -e
printf '%s\n' "$cargo_status" > "$MRK_MACOS_WORK/normal-build.status"
/usr/bin/tail -c 65536 "$MRK_MACOS_WORK/normal-build.stderr" > "$MRK_MACOS_WORK/normal-build.stderr.tail.txt"
[[ "$cargo_status" == 0 ]] || exit "$cargo_status"
# Keep the original Cargo dylib unsigned; the stager binds its exact
# completed artifact and copies it before nested image signing.
image_sha=$(/usr/bin/shasum -a 256 "$CARGO_TARGET_DIR/$MRK_MACOS_TARGET/release/libmrk_desktop_image.dylib")
image_sha=${image_sha%% *}
[[ "$image_sha" =~ ^[0-9a-f]{64}$ ]] || exit 1
printf 'MRK_MACOS_DESKTOP_IMAGE_SHA256=%s\n' "$image_sha" >> "$GITHUB_ENV"
fi
remover_features=macos-installed-remover
if [[ "$GITHUB_REF" == refs/heads/verify/desktop-macos-removal-lifecycle && "$MRK_MACOS_REMOVAL_CASE" == abrupt ]]; then
  remover_features=macos-installed-removal-abrupt-fixture
fi
# Same architecture-selected app-build budget; no independent timeout entitlement.
# This current SOURCE role cannot embed its not-yet-created inventory.
set +e
PATH="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin:/usr/bin:/bin:/usr/sbin:/sbin" RUSTC="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin/rustc" RUSTUP_TOOLCHAIN="$RUSTUP_TOOLCHAIN" RUSTUP_AUTO_INSTALL=0 CARGO_HOME=/Users/runner/.cargo RUSTUP_HOME=/Users/runner/.rustup CARGO_TARGET_DIR="$MRK_MACOS_WORK/remover-target" /usr/bin/env -u MRK_MACOS_INSTALL_INVENTORY_SHA256 "/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin/cargo" build \
  --locked --offline --release --jobs 1 --no-default-features --features "$remover_features" --bin mrk-macos-remove \
  --target "$MRK_MACOS_TARGET" --message-format=json-render-diagnostics \
  > "$MRK_MACOS_WORK/remover-build.jsonl" 2> "$MRK_MACOS_WORK/remover-build.stderr"
remover_status=$?
printf '%s\n' "$remover_status" > "$MRK_MACOS_WORK/remover-build.status"
remover_status_saved=$?
set -e
if [[ "$remover_status" != 0 ]]; then
  # Optional diagnostics cannot replace the original compiler status.
  set +e
  printf 'Fixed remover compiler failed with original status %s; bounded diagnostics are retained.\n' "$remover_status" >&2
  exit "$remover_status"
fi
[[ "$remover_status_saved" == 0 ]] || exit "$remover_status_saved"
# Separate read-only CLI graph; same selected compiler and app-build
# budget. It never starts the service or grants a project access.
set +e
PATH="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin:/usr/bin:/bin:/usr/sbin:/sbin" RUSTC="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin/rustc" RUSTUP_TOOLCHAIN="$RUSTUP_TOOLCHAIN" RUSTUP_AUTO_INSTALL=0 CARGO_HOME=/Users/runner/.cargo RUSTUP_HOME=/Users/runner/.rustup CARGO_TARGET_DIR="$MRK_MACOS_WORK/installed-cli-target" "/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin/cargo" build \
  --locked --offline --release --jobs 1 --no-default-features --features installed-cli --bin mrk \
  --target "$MRK_MACOS_TARGET" --message-format=json-render-diagnostics \
  > "$MRK_MACOS_WORK/installed-cli-build.jsonl" 2> "$MRK_MACOS_WORK/installed-cli-build.stderr"
cli_status=$?
printf '%s\n' "$cli_status" > "$MRK_MACOS_WORK/installed-cli-build.status"
cli_status_saved=$?
set -e
if [[ "$cli_status" != 0 ]]; then
  printf 'Fixed installed CLI compiler failed with original status %s; originals remain local.\n' "$cli_status" >&2 || :
  exit "$cli_status"
fi
[[ "$cli_status_saved" == 0 ]] || exit "$cli_status_saved"
if [[ "$GITHUB_REF" == refs/heads/verify/desktop-macos-removal-lifecycle ]]; then
  # Separate genuine nonshipping observer graph; same24min preparation step.
  # No key/signature/Installer execution and no target inventory substitution.
  set +e
  PATH="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin:/usr/bin:/bin:/usr/sbin:/sbin" RUSTC="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin/rustc" RUSTUP_TOOLCHAIN="$RUSTUP_TOOLCHAIN" RUSTUP_AUTO_INSTALL=0 CARGO_HOME=/Users/runner/.cargo RUSTUP_HOME=/Users/runner/.rustup CARGO_TARGET_DIR="$MRK_MACOS_WORK/removal-observer-target" /usr/bin/env -u MRK_MACOS_INSTALL_INVENTORY_SHA256 "/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin/cargo" build \
    --locked --offline --release --jobs 1 --no-default-features --features macos-installed-removal-observer --bin mrk-macos-remove \
    --target "$MRK_MACOS_TARGET" --message-format=json-render-diagnostics \
    > "$MRK_MACOS_WORK/removal-observer-build.jsonl" 2> "$MRK_MACOS_WORK/removal-observer-build.stderr"
  observer_status=$?
  printf '%s\n' "$observer_status" > "$MRK_MACOS_WORK/removal-observer-build.status"
  observer_status_saved=$?
  set -e
  if [[ "$observer_status" != 0 ]]; then exit "$observer_status"; fi
  [[ "$observer_status_saved" == 0 ]] || exit "$observer_status_saved"
fi
