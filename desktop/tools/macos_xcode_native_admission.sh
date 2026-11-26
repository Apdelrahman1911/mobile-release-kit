#!/bin/bash
# Existing fixed companion compile/verification, with no implicit default.
[[ $# == 1 ]] || exit 64
case "$1" in
compile)
set -euo pipefail
set -o noclobber
umask 077
[[ "$(/usr/bin/id -u)" != 0 ]]
target="$MRK_MACOS_WORK/xcode-native-admission-target"
[[ ! -e "$target" && ! -L "$target" ]]
/bin/mkdir -m 700 "$target"
export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
# Only the library-test graph. The actual selected libtest is retained
# for the post-Installer step, not run before the managed tree exists.
PATH="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
RUSTC="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin/rustc" \
RUSTUP_TOOLCHAIN="$RUSTUP_TOOLCHAIN" RUSTUP_AUTO_INSTALL=0 \
CARGO_HOME=/Users/runner/.cargo RUSTUP_HOME=/Users/runner/.rustup CARGO_TARGET_DIR="$target" \
  /usr/bin/env -u MRK_MACOS_INSTALL_INVENTORY_SHA256 -u MRK_MACOS_STORE_RUNTIME \
  "/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin/cargo" test \
    --locked --no-default-features --target "$MRK_MACOS_TARGET" \
    --manifest-path desktop/src-tauri/Cargo.toml --lib --no-run --message-format=json-render-diagnostics |
  "$MRK_PYTHON" -I -S -B -c '
import os, pathlib, re, stat, sys
checkout = pathlib.Path(os.environ["GITHUB_WORKSPACE"])
sys.path.insert(0, str(checkout / "desktop/tools"))
import stage_macos_installed as stage
limit = 8 * 1024 * 1024
data = sys.stdin.buffer.read(limit + 1)
if len(data) > limit:
    while sys.stdin.buffer.read(65536):
        pass
    raise SystemExit("native libtest compiler metadata exceeded limit")
rows = [row for row in stage.cargo_records(data) if row.get("executable") is not None]
assert len(rows) == 1, "expected one app-native libtest executable"
row = rows[0]
directory = checkout / "desktop/src-tauri"
selected = row["target"]
assert row.get("manifest_path") == str(directory / "Cargo.toml")
assert selected.get("name") == "mobile_release_desktop"
assert selected.get("kind") == ["lib"] and selected.get("crate_types") == ["lib"]
assert selected.get("src_path") == str(directory / "src/lib.rs")
stage.cargo_profile(row, test=True)
stage.cargo_features(row, [])
executable = pathlib.Path(row["executable"])
target = pathlib.Path(os.environ["MRK_MACOS_WORK"]) / "xcode-native-admission-target"
assert executable.is_absolute() and executable.parent == target / os.environ["MRK_MACOS_TARGET"] / "debug/deps"
assert re.fullmatch(r"mobile_release_desktop-[0-9a-f]+", executable.name)
assert row.get("filenames") == [str(executable)] and executable.resolve(strict=True) == executable
original = executable.lstat()
assert stat.S_ISREG(original.st_mode) and original.st_uid == os.getuid() != 0 and original.st_nlink == 1 and original.st_mode & 0o111
print(executable)
' > "$MRK_MACOS_WORK/xcode-native-admission-executable.txt"
;;
verify)
set -euo pipefail
set -o noclobber
umask 077
[[ "$(/usr/bin/id -u)" != 0 ]]
IFS= read -r native_test < "$MRK_MACOS_WORK/xcode-native-admission-executable.txt"
expected="$MRK_MACOS_WORK/xcode-native-admission-target/$MRK_MACOS_TARGET/debug/deps"
[[ "${native_test%/*}" == "$expected" && "${native_test##*/}" =~ ^mobile_release_desktop-[0-9a-f]+$ ]]
[[ -f "$native_test" && ! -L "$native_test" && -x "$native_test" ]]
# Same actual compiled library test, current provider SOURCE. Not an
# installed-image result or an archive/signing claim. No tool launch.
"$native_test" \
  installed_runtime::ios_upload_tools_tests::ios_managed_archive_actual_tools_pre_post_and_positive_consume \
  installed_runtime::ios_upload_tools_tests::ios_upload_actual_selected_tools_pre_post_and_positive_consume \
  --exact --include-ignored --test-threads=1 | tee "$MRK_MACOS_WORK/xcode-native-admission-tests.log"
grep -Eq '^test result: ok\. 2 passed; 0 failed; 0 ignored;' "$MRK_MACOS_WORK/xcode-native-admission-tests.log"
# Only after actual compiler/test success: retire this new target,
# never the managed Xcode, signed inputs, or other job directories.
"$MRK_PYTHON" -I -S -B - <<'PY_XCODE_NATIVE_CLEAN'
import os, re, shutil, stat
from pathlib import Path
root = Path(os.environ['MRK_MACOS_WORK'])
assert root.parent == Path('/Users/runner/work/_temp') and re.fullmatch(r'mrk-macos-installed\.[A-Za-z0-9]{8}', root.name)
assert shutil.rmtree.avoids_symlink_attacks
fd = os.open(root, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_DIRECTORY)
try:
    original = os.fstat(fd)
    key = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)
    assert key(original) == key(root.lstat()) and original.st_uid == os.getuid() != 0 and stat.S_IMODE(original.st_mode) == 0o700
    current = os.stat('xcode-native-admission-target', dir_fd=fd, follow_symlinks=False)
    assert stat.S_ISDIR(current.st_mode) and current.st_uid == os.getuid() and current.st_dev == original.st_dev
    assert stat.S_IMODE(current.st_mode) == 0o700
    shutil.rmtree('xcode-native-admission-target', dir_fd=fd)
    assert key(os.fstat(fd)) == key(root.lstat()) == key(original)
    try: os.stat('xcode-native-admission-target', dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError: pass
    else: raise ValueError('native admission target retirement incomplete')
finally:
    os.close(fd)
PY_XCODE_NATIVE_CLEAN
;;
*) exit 64 ;;
esac
