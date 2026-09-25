#!/usr/bin/python3
"""One fresh G Linux libtest artifact from the original bounded no-run Cargo log.

DATA observer only: no compiler, candidate module or artifact is executed here.
Reuses the existing headless root/profile/sha2/fresh-artifact reconciliation.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

# Supplement the parent's pre-use protected mount; do not read control DATA on
# a different entry profile, and do not claim this undoes startup imports.
if (len(sys.argv) != 2 or sys.argv[1] != 'libtest'
        or not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
                and type(sys.pycache_prefix) is str
                and sys.pycache_prefix == '/run/mrk-gnome-python-empty-pycache-v1')):
    raise SystemExit('Fixed isolated artifact observer invocation required')

SOURCE = Path('/source')
TARGET = Path('/tmp/target')
REGISTRY = set(json.loads(Path('/inputs.json').read_bytes())['registryPackages'])
LOCAL = {
    'path+file://' + str(SOURCE / 'desktop/src-tauri') + '#mobile-release-kit-desktop@0.1.0',
    'path+file://' + str(SOURCE / 'desktop/vendor/secret-service-5.2.0') + '#secret-service@5.2.0',
    'path+file://' + str(SOURCE / 'desktop/vendor/zbus-5.19.0') + '#zbus@5.19.0',
    'path+file://' + str(SOURCE / 'desktop/native/linux-mount-observation') + '#mrk-linux-mount-observation@0.1.0',
}


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def data(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != 0 or before.st_gid != 0 or not 0 < before.st_size < limit):
            raise RuntimeError('Original DATA shape/bound differs')
        parts, remaining = [], before.st_size + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            parts.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(parts)
        if (len(raw) != before.st_size or identity(before) != identity(os.fstat(fd))
                or identity(before) != identity(path.lstat())):
            raise RuntimeError('Original DATA changed while reading')
        return raw, identity(before)
    finally:
        os.close(fd)


phase = 'libtest'
is_test = True
raw, _ = data(Path('/tmp/' + phase + '-compile.log'), 4194304)
if not raw.endswith(b'\n'):
    raise SystemExit('Incomplete original compiler log')
rows = [json.loads(line) for line in raw.decode('utf-8').splitlines() if line.startswith('{')]
finished = [row for row in rows if row.get('reason') == 'build-finished']
if len(finished) != 1 or finished[0].get('success') is not True:
    raise SystemExit('One original successful build-finished required')
if any(row.get('reason') == 'compiler-message' and row.get('message', {}).get('level') == 'error' for row in rows):
    raise SystemExit('Original Cargo log contains a compiler error')
artifacts = [row for row in rows if row.get('reason') == 'compiler-artifact']
registry = {row['package_id'].split('#', 1)[1] for row in artifacts if row['package_id'].startswith('registry+')}
local = {row['package_id'] for row in artifacts if not row['package_id'].startswith('registry+')}
if registry != REGISTRY or local != LOCAL:
    raise SystemExit('Existing Linux headless dependency graph differs')
root = [row for row in artifacts if row.get('manifest_path') == str(SOURCE / 'desktop/src-tauri/Cargo.toml')
        and row.get('target', {}).get('kind') == ['lib'] and row.get('profile', {}).get('test') is is_test]
if len(root) != 1:
    raise SystemExit('One original root libtest artifact required')
root = root[0]
if (root.get('fresh') is not False or root.get('features') != []
        or root['target'].get('name') != 'mobile_release_desktop'
        or root['target'].get('src_path') != str(SOURCE / 'desktop/src-tauri/src/lib.rs')
        or root['profile'].get('opt_level') != '0' or root['profile'].get('debuginfo') != 0
        or root['profile'].get('debug_assertions') is not True or root['profile'].get('overflow_checks') is not True):
    raise SystemExit('Fresh feature-off root/profile differs')
sha2 = [row for row in artifacts if row['package_id'].endswith('#sha2@0.10.9') and row['target'].get('kind') == ['lib']]
if (len(sha2) != 1 or sha2[0]['profile'].get('opt_level') != '3'
        or sha2[0]['profile'].get('test') is not False or sha2[0]['profile'].get('debug_assertions') is not True
        or sha2[0]['profile'].get('overflow_checks') is not True):
    raise SystemExit('Existing optimized sha2 test dependency profile differs')
zbus = [row for row in artifacts if row['package_id'] == 'path+file://' + str(SOURCE / 'desktop/vendor/zbus-5.19.0') + '#zbus@5.19.0' and row['target'].get('kind') == ['lib']]
expected_zbus_features = ['blocking-api', 'mrk-owned-test-support', 'tokio']
if len(zbus) != 1 or zbus[0].get('features') != expected_zbus_features or zbus[0]['profile'].get('test') is not False:
    raise SystemExit('One maintained zbus with the exact libtest feature fence required')
# Exact retained stable Tokio graph; the declared tracing feature is present,
# but Tokio trace/taskdump hooks require tokio_unstable. The frozen command has
# no custom cfgs or inherited Cargo/Rust configuration; root also reviews the
# Keyring supported_target fence. This observer does not infer cfgs from features.
tokio = [row for row in artifacts if row['package_id'].endswith('#tokio@1.48.0')
         and row['target'].get('kind') == ['lib']]
expected_tokio_features = ['bytes', 'default', 'fs', 'io-util', 'libc', 'macros', 'mio', 'net', 'process', 'rt', 'rt-multi-thread', 'signal-hook-registry', 'socket2', 'sync', 'time', 'tokio-macros', 'tracing']
if (len(tokio) != 1 or tokio[0].get('features') != expected_tokio_features
        or tokio[0]['profile'].get('test') is not False):
    raise SystemExit('Exact retained Tokio stable feature graph differs')
if any(row.get('reason') == 'build-script-executed'
       and any(value.split('=', 1)[0].strip() in ('loom', 'tokio_unstable')
               for value in row.get('cfgs', [])) for row in rows):
    raise SystemExit('Unadmitted diagnostic cfg in original compiler graph')
# Retain the exact libtest SDK/crypto feature graph. This focused carrier makes
# no normal-build or shipping-graph claim.
secret = [row for row in artifacts if row['package_id'] ==
          'path+file://' + str(SOURCE / 'desktop/vendor/secret-service-5.2.0') + '#secret-service@5.2.0'
          and row['target'].get('kind') == ['lib']]
expected_secret_features = ['crypto-rust', 'mrk-retrieval-test-support', 'rt-tokio', 'rt-tokio-crypto-rust']
if (len(secret) != 1 or secret[0].get('features') != expected_secret_features
        or secret[0]['profile'].get('test') is not False):
    raise SystemExit('Exact libtest Secret Service feature fence differs')
expected_crypto_features = {'aes@0.9.2': ['zeroize'], 'cbc@0.2.1': ['alloc', 'block-padding', 'default', 'zeroize'], 'cipher@0.5.2': ['alloc', 'block-padding', 'zeroize'], 'crypto-common@0.2.2': ['zeroize'], 'hybrid-array@0.4.14': ['zeroize'], 'zeroize@1.9.0': ['alloc']}
for package, expected in expected_crypto_features.items():
    selected = [row for row in artifacts if row['package_id'].startswith('registry+')
                and row['package_id'].split('#', 1)[1] == package and row['target'].get('kind') == ['lib']]
    if (len(selected) != 1 or selected[0].get('features') != expected
            or selected[0]['profile'].get('test') is not False):
        raise SystemExit('Exact retrieval crypto feature closure differs: ' + package)
executable = root.get('executable')
if (type(executable) is not str or not re.fullmatch(
        r'/tmp/target/x86_64-unknown-linux-gnu/debug/deps/mobile_release_desktop-[0-9a-f]{16}', executable)
        or executable not in root.get('filenames', [])):
    raise SystemExit('Original executable is outside the fresh fixed target')
body, original = data(Path(executable), 128 << 20)
if not original[2] & 0o111:
    raise SystemExit('Original compiler output is not executable')
artifact = {'path': executable, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'identity': original}
# Full expanded carrier index;964 is only the unchanged product subset.
index, _ = data(Path('/app-sources.sha256'), 262144)
binding_raw, _ = data(Path('/source-binding.json'), 1 << 20)
binding = json.loads(binding_raw)
if (binding['schema'] != 'gnome-session-source-binding-1'
        or binding['productTree'] != '4f809afa38b6b814e8c8110df5599cbf5bc97677'
        or binding['productFiles'] != 964
        or not 964 < binding['completeSourceFiles'] <= 1024
        or binding['completeSourceFiles'] != len(binding['sourceFiles'])
        or binding['sourceIndexSha256'] != hashlib.sha256(index).hexdigest()):
    raise SystemExit('Original hosted complete-source binding differs')
report = {'scope': 'gnome-transport-libtest-headless-compile-only', 'phase': phase, 'zbusFeatures': expected_zbus_features, 'testSupportEnabled': is_test, 'source': str(SOURCE),
          'sourceIndexSha256': hashlib.sha256(index).hexdigest(),
          'prospectiveTree': binding['fullTree'], 'completeSourceFiles': binding['completeSourceFiles'],
          'productTree': binding['productTree'], 'productFiles': binding['productFiles'],
          'sourceBindingSha256': hashlib.sha256(binding_raw).hexdigest(),
          'originalIndexStageSha256': binding['gitIndexSha256'],
          'compileLogBytes': len(raw), 'compileLogSha256': hashlib.sha256(raw).hexdigest(),
          'features': [], 'registryPackages': sorted(registry), 'sha2Profile': sha2[0]['profile'], 'tokioFeatures': expected_tokio_features,
          'secretServiceFeatures': expected_secret_features, 'cryptoFeatures': expected_crypto_features,
          'artifact': artifact,
          'artifactExecuted': False, 'nativeQualified': False}
print(json.dumps(report, sort_keys=True, separators=(',', ':')))
