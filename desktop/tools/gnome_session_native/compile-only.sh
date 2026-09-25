#!/usr/bin/bash
# Accepted G SOURCE03: fresh headless libtest only; DATA2 is NOT repeated by this native carrier.
set -euo pipefail
set -C
umask 077
test "$#" -eq 0
G=/source
T=/inputs/rust
cd /tmp
test ! -e /tmp/target; test ! -L /tmp/target
/run/mrk-gnome-controller-runtime-v2/python/bin/python3 -I -S -B -X pycache_prefix=/run/mrk-gnome-python-empty-pycache-v1 /prepare.py prepare
/usr/bin/sha256sum --strict --quiet --check /app-sources.sha256
printf 'VAULT_FINALITY_RUST_SOURCE_PRE=complete-hosted-source-binding-index-matched\n'
export PATH="$T/bin:/usr/bin:/bin" HOME=/tmp/home TMPDIR=/tmp/work TMP=/tmp/work TEMP=/tmp/work
export CARGO_HOME=/tmp/cargo RUSTUP_HOME=/tmp/rustup RUSTC="$T/bin/rustc"
export CARGO_NET_OFFLINE=true RUSTFLAGS='-C debuginfo=0' CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
cd /tmp/neutral
for phase in libtest; do
    cargo_mode=(test --no-run)
    printf 'VAULT_FINALITY_COMPILE_BEGIN=%s\n' "$phase"
    set +e
    /usr/bin/timeout --signal=TERM --kill-after=10s 420s \
        "$T/bin/cargo" "${cargo_mode[@]}" --locked --offline --lib --no-default-features -j1 \
        --target x86_64-unknown-linux-gnu --manifest-path "$G/desktop/src-tauri/Cargo.toml" \
        --target-dir /tmp/target --message-format=json-render-diagnostics --color=never \
        </dev/null 2>&1 | /usr/bin/head -c 4194304 > "/tmp/$phase-compile.log"
    compile_status=("${PIPESTATUS[@]}")
    set -e
    /usr/bin/cat "/tmp/$phase-compile.log"
    printf 'VAULT_FINALITY_COMPILE_WAITS=%s:{"originalCargoEnvelopeExit":%d,"logReaderExit":%d}\n' "$phase" "${compile_status[0]}" "${compile_status[1]}"
    (( compile_status[0] == 0 && compile_status[1] == 0 ))
    [[ $(/usr/bin/stat -c %s "/tmp/$phase-compile.log") -lt 4194304 ]]
    /usr/bin/sha256sum --strict --quiet --check /app-sources.sha256
    receipt=/tmp/artifact.json
    (
        ulimit -v 262144; ulimit -t 10; ulimit -n 128; ulimit -c 0; ulimit -f 64
        exec /usr/bin/timeout --signal=TERM --kill-after=5s 30s \
            /run/mrk-gnome-controller-runtime-v2/python/bin/python3 -I -S -B -X pycache_prefix=/run/mrk-gnome-python-empty-pycache-v1 /check-compile.py "$phase"
    ) > "$receipt"
    printf 'VAULT_FINALITY_RUST_ARTIFACT=%s:' "$phase"; /usr/bin/cat "$receipt"
done
