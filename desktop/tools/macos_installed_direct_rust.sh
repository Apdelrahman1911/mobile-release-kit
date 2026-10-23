#!/bin/bash
set -euo pipefail
# The hosted stable alias moves when the runner image updates. Install
# the already-reviewed exact compiler, without changing that alias.
case "$MRK_MACOS_TARGET:$RUSTUP_TOOLCHAIN" in
  aarch64-apple-darwin:1.98.1|x86_64-apple-darwin:1.98.0) ;;
  *) echo 'Unsupported pinned Mac compiler selection' >&2; exit 1 ;;
esac
# New hosted images keep rustup in its Homebrew keg, not ~/.cargo/bin.
# Select once before entry; an unusable legacy launcher is not a fallback.
rustup_directory=/Users/runner/.cargo/bin
if [[ ! -e "$rustup_directory/rustup" && ! -L "$rustup_directory/rustup" ]]; then
  case "$MRK_MACOS_TARGET" in
    aarch64-apple-darwin) rustup_directory=/opt/homebrew/opt/rustup/bin ;;
    x86_64-apple-darwin) rustup_directory=/usr/local/opt/rustup/bin ;;
  esac
fi
if [[ ! -f "$rustup_directory/rustup" || ! -x "$rustup_directory/rustup" ]]; then
  echo 'Pinned Mac Rust bootstrap unavailable' >&2; exit 1
fi
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME=/Users/runner \
  CARGO_HOME=/Users/runner/.cargo RUSTUP_HOME=/Users/runner/.rustup \
  "$rustup_directory"/rustup toolchain install "$RUSTUP_TOOLCHAIN" \
  --profile minimal --no-self-update
# Packaged rustup installs toolchains but need not create Cargo's home.
# Never repair an existing entry; the unchanged no-follow admission follows.
if [[ ! -e /Users/runner/.cargo && ! -L /Users/runner/.cargo ]]; then
  /bin/mkdir -m 700 /Users/runner/.cargo
fi
"$MRK_PYTHON" -I -S -B - <<'PY_DIRECT_RUST'
import importlib.util, os, re, stat, subprocess, sys, tomllib
from pathlib import Path

checkout = Path('/Users/runner/work/mobile-release-kit/mobile-release-kit')
home = Path('/Users/runner')
cargo_home, rustup_home = home / '.cargo', home / '.rustup'
build_target = os.environ['MRK_MACOS_TARGET']
machines = {'aarch64-apple-darwin': 'arm64', 'x86_64-apple-darwin': 'x86_64'}
if build_target not in machines: raise ValueError('direct-rust-target')
rust_tuples = {
    "aarch64-apple-darwin": ("1.98.1", "48a229ceaefd4985c50990b14116b6d856af0985"),
    "x86_64-apple-darwin": ("1.98.0", "88d9e12ae178fab0fb5cc050a94da85685d449ea"),
}
rust_release, rust_commit = rust_tuples[build_target]
bin_directory = rustup_home / ('toolchains/' + rust_release + '-' + build_target + '/bin')
compiler_path = str(bin_directory) + ':/usr/bin:/bin:/usr/sbin:/sbin'
def need(value, reason):
    if not value: raise ValueError(reason)
need(sys.platform == 'darwin' and sys.maxsize == 2**63-1 and os.uname().machine == machines[build_target]
     and os.getuid() != 0 and os.getuid() == os.geteuid() and os.getgid() == os.getegid(), 'direct-rust-host')
need(os.environ.get('HOME') == str(home) and os.environ.get('GITHUB_WORKSPACE') == str(checkout)
     and os.environ.get('RUSTUP_TOOLCHAIN') == rust_release
     and os.environ.get('CARGO_HOME', str(cargo_home)) == str(cargo_home)
     and os.environ.get('RUSTUP_HOME', str(rustup_home)) == str(rustup_home)
     and os.environ.get('RUSTC', str(bin_directory / 'rustc')) == str(bin_directory / 'rustc')
     and os.environ.get('RUSTUP_AUTO_INSTALL', '0') == '0', 'direct-rust-source-route')
allowed_cargo = {'CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_INCREMENTAL'}
allowed_rust = {'RUSTC', 'RUSTUP_HOME', 'RUSTUP_TOOLCHAIN', 'RUSTUP_AUTO_INSTALL'}
need(not any((key.startswith('CARGO_') and key not in allowed_cargo)
             or (key.startswith('RUST') and key not in allowed_rust) for key in os.environ), 'direct-rust-ambient-selector')
need(os.environ.get('CARGO_INCREMENTAL', '0') == '0'
     and os.environ.get('CARGO_TARGET_DIR') == str(Path(os.environ['MRK_MACOS_WORK']) / 'cargo-target'), 'direct-rust-target-route')
cwd_names = ('desktop/src-tauri', 'desktop/native/macos-installed-native',
             'desktop/helpers/macos-android-register', 'desktop/helpers/macos-desktop-image',
             'desktop/helpers/macos-vault-helper')
flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
originals, directories, absent, close_errors = [], {}, set(), []
pending_call = False
failure = None
def signature(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)
def current(row):
    need(row['fd'] is not None and row['identity'] is not None, 'direct-rust-original-unbound')
    parent = row['parent']
    named = os.stat(str(row['path']) if parent is None else row['path'].name,
                    dir_fd=None if parent is None else parent['fd'], follow_symlinks=False)
    width = len(row['identity'])
    need(signature(os.fstat(row['fd']))[:width] == row['identity']
         == signature(named)[:width], 'direct-rust-original-changed')
def directory(path):
    if path in directories:
        current(directories[path]); return directories[path]
    need(path.is_absolute() and str(path) == os.path.normpath(path) and len(path.parts) <= 24
         and len(originals) < 96, 'direct-rust-fixed-directory-bound')
    parent = None if path == Path('/') else directory(path.parent)
    need(len(originals) < 96, 'direct-rust-original-bound')
    fd = os.open(str(path) if parent is None else path.name, flags | os.O_DIRECTORY,
                 dir_fd=None if parent is None else parent['fd'])
    row = {'fd': fd, 'path': path, 'parent': parent, 'identity': None, 'closed': False}
    originals.append(row)
    info = os.fstat(fd)
    need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
         and not info.st_mode & 0o022, 'direct-rust-directory-policy')
    row['identity'] = signature(info)[:5]
    directories[path] = row
    current(row)
    return row
def original_file(path, *, executable=False):
    parent = directory(path.parent)
    need(len(originals) < 96, 'direct-rust-original-bound')
    fd = os.open(path.name, flags, dir_fd=parent['fd'])
    row = {'fd': fd, 'path': path, 'parent': parent, 'identity': None, 'closed': False}
    originals.append(row)
    info = os.fstat(fd)
    need(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid())
         and not info.st_mode & 0o022 and info.st_nlink > 0
         and (not executable or info.st_mode & 0o111), 'direct-rust-file-policy')
    row['identity'] = signature(info)
    current(row)
    return row
def no_configuration():
    searched = {cargo_home}
    for name in cwd_names:
        cwd = checkout / name
        searched.update(parent / '.cargo' for parent in (cwd, *cwd.parents))
    need(len(searched) <= 32, 'direct-rust-configuration-bound')
    for path in sorted(searched):
        parent = directory(path.parent)
        try: info = os.stat(path.name, dir_fd=parent['fd'], follow_symlinks=False)
        except FileNotFoundError:
            need(path not in directories, 'direct-rust-configuration-disappeared')
            absent.add(path); continue
        need(path not in absent and stat.S_ISDIR(info.st_mode), 'direct-rust-configuration-directory')
        held = directory(path)
        for name in ('config', 'config.toml', 'credentials', 'credentials.toml'):
            try: os.stat(name, dir_fd=held['fd'], follow_symlinks=False)
            except FileNotFoundError: pass
            else: raise ValueError('direct-rust-ambient-configuration')
def check_originals():
    for row in originals: current(row)

stage = "input-files"
try:
    directory(cargo_home); directory(rustup_home); directory(bin_directory)
    selected = original_file(checkout / 'desktop/rust-toolchain.toml')
    size = selected['identity'][6]
    need(0 < size <= 4096, 'direct-rust-repository-default-bound')
    raw = os.pread(selected['fd'], size + 1, 0)
    need(len(raw) == size and os.pread(selected['fd'], 1, size) == b'', 'direct-rust-repository-default-read')
    current(selected)
    need(tomllib.loads(raw.decode('utf-8'))['toolchain']['channel'] == '1.98.0', 'direct-rust-repository-default')
    for tool in ('cargo', 'rustc'): original_file(bin_directory / tool, executable=True)
    stage = "configuration"
    no_configuration(); check_originals()
    stage = "owner-load"
    spec = importlib.util.spec_from_file_location('_mrk_direct_rust_existing_owner_loader', checkout / 'desktop/tools/macos_aqua_qualification.py')
    qualification = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = qualification
    spec.loader.exec_module(qualification)
    owner = qualification.load_owner(checkout)
    environment = dict(PATH=compiler_path, HOME=str(home), CARGO_HOME=str(cargo_home), RUSTUP_HOME=str(rustup_home),
                       RUSTC=str(bin_directory / 'rustc'), RUSTUP_TOOLCHAIN=rust_release, RUSTUP_AUTO_INSTALL='0',
                       LANG='C', LC_ALL='C', TZ='UTC', DEVELOPER_DIR=os.environ['DEVELOPER_DIR'],
                       MACOSX_DEPLOYMENT_TARGET=os.environ['MACOSX_DEPLOYMENT_TARGET'])
    for tool in ('rustc', 'cargo'):
        stage = tool + '-version'
        no_configuration(); check_originals()
        argv = [str(bin_directory / tool), '--version', '--verbose']
        pending_call = True
        result = owner.run_owned(argv, environ=environment, cwd=checkout / 'desktop/src-tauri',
                                 timeout=15, capture=True, text=False, output_limit=4096)
        need(type(result) is subprocess.CompletedProcess and type(result.args) is list and result.args == argv
             and type(result.returncode) is int and type(result.stdout) is bytes and type(result.stderr) is bytes
             and len(result.stdout) + len(result.stderr) <= 4096, 'direct-rust-original-return')
        pending_call = False  # Only this original complete return settles the command.
        need(result.returncode == 0 and not result.stderr and result.stdout, 'direct-rust-version-return')
        lines = result.stdout.decode('utf-8', 'strict').strip().splitlines()
        need(lines[0].startswith(tool + ' ') and [line for line in lines if line.partition(':')[0].strip() == 'release'] == ['release: ' + rust_release]
             and [line for line in lines if line.partition(':')[0].strip() == 'host'] == ['host: ' + build_target], 'direct-rust-version-host')
        if tool == 'rustc':
            need([line for line in lines if line.partition(':')[0].strip() == 'commit-hash'] == ['commit-hash: ' + rust_commit], 'direct-rust-clock-commit')
        no_configuration(); check_originals()
except BaseException as error:
    failure = error
finally:
    # No second query or manual retirement after an unreturned original. The
    # original Python process's kernel exit releases retained read-only FDs.
    if not pending_call:
        for row in reversed(originals):
            fd, row['fd'] = row['fd'], None  # One consuming close, never retry.
            if fd is None: continue
            try: os.close(fd); row['closed'] = True
            except OSError: close_errors.append('direct-rust-close-unknown')
if failure is not None or pending_call or close_errors or not all(row['closed'] for row in originals):
    # Only fixed source labels; never exception prose or private output.
    allowed = ('direct-rust-ambient-configuration', 'direct-rust-ambient-selector', 'direct-rust-clock-commit', 'direct-rust-close-unknown', 'direct-rust-configuration-bound', 'direct-rust-configuration-directory', 'direct-rust-configuration-disappeared', 'direct-rust-directory-policy', 'direct-rust-file-policy', 'direct-rust-fixed-directory-bound', 'direct-rust-host', 'direct-rust-original-bound', 'direct-rust-original-changed', 'direct-rust-original-return', 'direct-rust-original-unbound', 'direct-rust-repository-default', 'direct-rust-repository-default-bound', 'direct-rust-repository-default-read', 'direct-rust-source-route', 'direct-rust-target', 'direct-rust-target-route', 'direct-rust-version-host', 'direct-rust-version-return')
    args = BaseException.args.__get__(failure) if failure is not None else ()
    reason = (args[0] if type(failure) is ValueError and type(args) is tuple
              and len(args) == 1 and type(args[0]) is str and args[0] in allowed else
              "original-pending" if pending_call else "close-unknown" if close_errors else "unclassified")
    raise SystemExit('Pinned Rust admission refused: ' + reason + '; stage=' + stage)
print('Fixed direct Rust' + rust_release + ' compiler and Cargo admitted from the versioned installation.')
PY_DIRECT_RUST
