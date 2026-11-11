set -euo pipefail
[[ "$MRK_MACOS_TARGET:$RUSTUP_TOOLCHAIN" == aarch64-apple-darwin:1.98.1 ]]
rustup_directory=/Users/runner/.cargo/bin
if [[ ! -e "$rustup_directory/rustup" && ! -L "$rustup_directory/rustup" ]]; then
  rustup_directory=/opt/homebrew/opt/rustup/bin
fi
[[ -f "$rustup_directory/rustup" && -x "$rustup_directory/rustup" ]]
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME=/Users/runner \
  CARGO_HOME=/Users/runner/.cargo RUSTUP_HOME=/Users/runner/.rustup \
  "$rustup_directory/rustup" toolchain install 1.98.1 --profile minimal --no-self-update
if [[ ! -e /Users/runner/.cargo && ! -L /Users/runner/.cargo ]]; then
  /bin/mkdir -m 700 /Users/runner/.cargo
fi
# Actual version, commit and no-follow file admission remain in preparation.
