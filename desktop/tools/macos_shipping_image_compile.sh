set -euo pipefail
set +x
set +a
umask 077
"$MRK_PYTHON" -I -S -B - <<'PY_SHIPPING_IMAGE_COMPILE'
import hashlib, importlib.util, json, math, os, re, shutil, stat, subprocess, sys, time, tomllib
from pathlib import Path

def compile_public_data(value, source, run_id, run_attempt):
    """Closed prior compile observations, never receipt-publication authority."""
    def check(ok):
        need(ok, 'compile-public-data')

    def digest(item):
        check(type(item) is str and re.fullmatch(r'[0-9a-f]{64}', item) is not None)
        return item

    def integer(item, low, high):
        check(type(item) is int and low <= item <= high)
        return item

    def nullable_bool(item):
        check(item is None or type(item) is bool)
        return item

    roles = ('node-version', 'npm-version', 'rustc-version', 'cargo-version',
             'npm-ci', 'frontend-build', 'shipping-image-build')
    fact_names = ('originalPending', 'sourcePost', 'toolsPost', 'frontendGenerated',
                  'facadeArtifactVerified', 'inputOriginalsKnown', 'toolOriginalsClosed',
                  'generatedOutputsRetired', 'shippingGraphCompiled', 'installedQualified',
                  'runtimeQualified', 'launched', 'signed', 'pythonControllerPrepared',
                  'pythonControllerPost', 'pythonControllerRetired')
    conditions = ('controller-record', 'controller-base', 'controller-row', 'controller-roster',
                  'controller-file', 'controller-config', 'controller-runtime', 'controller-original-changed',
                  'controller-total', 'controller-directory', 'controller-short-read', 'controller-deadline',
                  'controller-unexpected-process', 'controller-work-root', 'controller-template',
                  'controller-publication', 'controller-source-copy', 'controller-operation',
                  'cargo-output-bound', 'cargo-line-bound', 'cargo-document', 'cargo-finished',
                  'cargo-facade-count', 'cargo-target-shape', 'cargo-real-facade', 'cargo-app-count',
                  'cargo-shipping-feature', 'compile-artifact-file', 'compile-artifact-short', 'compile-artifact-post')
    owner_reasons = ('incomplete-output', 'output-bound', 'protocol-or-ownership',
                     'command-failed-or-incomplete', 'cleanup-unconfirmed', 'exec-rejected',
                     'stopped-before-exec', 'parent-ended', 'observer-ended', 'fence-collision', 'unknown')
    check(type(value) is dict and type(source) is str and re.fullmatch(r'[0-9a-f]{40}', source)
          and source != '0' * 40 and all(type(item) is str and re.fullmatch(r'[1-9][0-9]{0,19}', item)
                                       for item in (run_id, run_attempt)))
    fixed = dict(schemaVersion=1, scope='fixed-arm-shipping-image-compile-only', source=source,
                 workflowSource=source, runId=run_id, runAttempt=run_attempt, target='aarch64-apple-darwin')
    check(type(value.get('schemaVersion')) is int and all(value.get(key) == item for key, item in fixed.items()))
    facts = {}
    for name in fact_names:
        check(name not in value or type(value[name]) is bool)
        facts[name] = value.get(name)
    check(type(facts['shippingGraphCompiled']) is bool
          and all(facts[name] is False for name in ('installedQualified', 'runtimeQualified', 'launched', 'signed')))
    rows = value.get('commands')
    check(type(rows) is list and len(rows) <= len(roles))
    commands = []
    for index, row in enumerate(rows):
        check(type(row) is dict and row.get('role') == roles[index]
              and type(row.get('returned')) is bool and type(row.get('capturesSettled')) is bool)
        out = integer(row.get('stdoutBytes'), 0, 4096 if index < 4 else 4 * 1024 * 1024)
        err = integer(row.get('stderrBytes'), 0, 4096 if index < 4 else 4 * 1024 * 1024)
        check(out + err <= (4096 if index < 4 else 4 * 1024 * 1024))
        commands.append(dict(role=roles[index], returned=row['returned'], capturesSettled=row['capturesSettled'],
                             returncode=integer(row.get('returncode'), -(2**31), 2**31 - 1),
                             stdoutBytes=out, stderrBytes=err,
                             stdoutSha256=digest(row.get('stdoutSha256')), stderrSha256=digest(row.get('stderrSha256'))))
    inventory = None
    if 'sourceInventoryBytes' in value or 'sourceInventorySha256' in value:
        inventory = dict(bytes=integer(value.get('sourceInventoryBytes'), 1, 2 * 1024 * 1024),
                         sha256=digest(value.get('sourceInventorySha256')))
    facade = None
    if 'facadeArtifact' in value:
        item = value['facadeArtifact']
        check(type(item) is dict)
        facade = dict(bytes=integer(item.get('bytes'), 1, 256 * 1024 * 1024), sha256=digest(item.get('sha256')))
    failure = None
    if value.get('failure') is not None:
        item = value['failure']
        check(type(item) is dict)
        stages = ('python-base', 'python-create', 'python-census', 'python-publication', 'admission',
                  'source-tool-post', 'generated-cleanup', 'tool-close', 'public-capture') + roles
        stage, condition = item.get('stage'), item.get('condition')
        check(type(stage) is str and (condition is None or type(condition) is str))
        failure = dict(stage=stage if stage in stages else 'other',
                       condition=condition if condition in conditions else None if condition is None else 'unclassified',
                       ownerDiagnostic=None)
        if 'ownerDiagnostic' in item:
            observed = item['ownerDiagnostic']
            check(type(observed) is dict and type(observed.get('available')) is bool)
            typed = observed.get('typedFacts', [])
            check(type(typed) is list and len(typed) <= 16
                  and (observed['available'] or not typed))
            projected = []
            for row in typed:
                check(type(row) is dict and type(row.get('kind')) is str and row['kind'] in ('process-error', 'interrupted')
                      and type(row.get('reason')) is str and row['reason'] in owner_reasons)
                mask = row.get('ownerFailureMask')
                check(mask is None or type(mask) is int and 1 <= mask <= 63)
                projected.append(dict(kind=row['kind'], reason=row['reason'], ownerFailureMask=mask,
                                      **{key: nullable_bool(row.get(key)) for key in ('dispatched', 'contained', 'cleanupComplete')}))
            failure['ownerDiagnostic'] = dict(available=observed['available'], typedFacts=projected,
                                              chainTruncated=nullable_bool(observed.get('chainTruncated')))
    if facts['shippingGraphCompiled']:
        check(len(commands) == len(roles) and all(row['returned'] and row['capturesSettled'] and row['returncode'] == 0 for row in commands)
              and facts['originalPending'] is False and failure is None and inventory is not None and facade is not None
              and all(facts[name] is True for name in ('sourcePost', 'toolsPost', 'frontendGenerated', 'facadeArtifactVerified',
                  'inputOriginalsKnown', 'toolOriginalsClosed', 'generatedOutputsRetired', 'pythonControllerPrepared',
                  'pythonControllerPost', 'pythonControllerRetired')))
    result = dict(kind='mrk-public-shipping-compile-evidence-v1', **fixed, facts=facts,
                  commands=commands, sourceInventory=inventory, facadeArtifact=facade, failure=failure)
    check(len((json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')) <= 16384)
    return result


TARGET = 'aarch64-apple-darwin'
RUST_RELEASE = '1.98.1'
RUST_COMMIT = '48a229ceaefd4985c50990b14116b6d856af0985'
ROLES = ('node-version', 'npm-version', 'rustc-version', 'cargo-version',
         'npm-ci', 'frontend-build', 'shipping-image-build')
CAPTURE = 4 * 1024 * 1024
SOURCE_LIMIT = 2 * 1024 * 1024
ARTIFACT_REASONS = ('cargo-output-bound', 'cargo-line-bound', 'cargo-document', 'cargo-finished',
                    'cargo-facade-count', 'cargo-target-shape', 'cargo-real-facade', 'cargo-app-count',
                    'cargo-shipping-feature', 'compile-artifact-file', 'compile-artifact-short', 'compile-artifact-post')


def need(value, reason):
    if not value: raise ValueError(reason)


# Fixed, disposable hosted-controller preparation, not a packaged Python runtime.
CONTROLLER_BASE = '/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
CONTROLLER_DIRS = ('', 'bin', 'include', 'lib', 'lib/python3.14', 'lib/python3.14/site-packages')
CONTROLLER_EXES = ('bin/python3.14', 'bin/python3', 'bin/python', 'bin/𝜋thon')
CONTROLLER_SCRIPTS = ('bin/Activate.ps1', 'bin/activate', 'bin/activate.fish', 'bin/activate.csh')
CONTROLLER_FILES = ('pyvenv.cfg',) + CONTROLLER_EXES + CONTROLLER_SCRIPTS
CONTROLLER_REASONS = ('controller-record', 'controller-base', 'controller-row', 'controller-roster',
                      'controller-file', 'controller-config', 'controller-runtime', 'controller-original-changed',
                      'controller-total', 'controller-directory', 'controller-short-read', 'controller-deadline',
                      'controller-unexpected-process', 'controller-work-root', 'controller-template',
                      'controller-publication', 'controller-source-copy', 'controller-operation')


def controller_config_data(work):
    root = str(work / 'python-controller')
    return ('home = ' + str(Path(CONTROLLER_BASE).parent) + '\n'
            'include-system-site-packages = false\nversion = 3.14.7\n'
            'executable = ' + CONTROLLER_BASE + '\n'
            'command = ' + CONTROLLER_BASE + ' -m venv --copies --without-pip --without-scm-ignore-files ' + root + '\n').encode('utf-8')


def controller_audit_data(event):
    return (event not in ('subprocess.Popen', 'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.exec')
            and not event.startswith('socket.'))


def controller_record_data(value, work, work_identity):
    need(type(value) is dict and set(value) == {'schemaVersion', 'baseExecutable', 'baseIdentity', 'baseSha256',
         'baseOriginalClosed', 'relativeExecutable', 'rows', 'totalBytes'}
         and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
         and value['baseExecutable'] == CONTROLLER_BASE and value['relativeExecutable'] == 'bin/python3.14'
         and value['baseOriginalClosed'] is True, 'controller-record')
    base = value['baseIdentity']
    need(type(base) is list and len(base) == 9 and all(type(item) is int and item >= 0 for item in base)
         and base[1] > 0 and base[2] in (stat.S_IFREG | 0o755, stat.S_IFREG | 0o775)
         and base[3:6] == [0, 80, 1] and 0 < base[6] <= 1024 * 1024
         and type(value['baseSha256']) is str and re.fullmatch(r'[0-9a-f]{64}', value['baseSha256']), 'controller-base')
    rows = value['rows']
    roster = CONTROLLER_DIRS + CONTROLLER_FILES
    need(type(rows) is list and len(rows) == len(roster) == 15, 'controller-roster')
    seen, total = set(), 0
    config = controller_config_data(work)
    for index, (row, name) in enumerate(zip(rows, roster, strict=True)):
        need(type(row) is dict and set(row) == {'path', 'identity', 'sha256'} and row['path'] == name,
             'controller-row')
        info = row['identity']
        need(type(info) is list and len(info) == 9 and all(type(item) is int and item >= 0 for item in info)
             and info[0] == work_identity[0] and info[1] > 0 and info[3:5] == list(work_identity[3:5])
             and tuple(info[:2]) not in seen, 'controller-row')
        seen.add(tuple(info[:2]))
        if index < len(CONTROLLER_DIRS):
            need(info[2] == stat.S_IFDIR | 0o700 and info[5] > 0 and row['sha256'] is None, 'controller-directory')
        else:
            executable = name in CONTROLLER_EXES
            need(info[2] == stat.S_IFREG | (0o755 if executable else 0o600) and info[5] == 1
                 and 0 < info[6] <= (1024 * 1024 if executable else 4096 if name == 'pyvenv.cfg' else 65536)
                 and type(row['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', row['sha256']), 'controller-file')
            if executable:
                need(info[6] == base[6] and row['sha256'] == value['baseSha256'], 'controller-source-copy')
            elif name == 'pyvenv.cfg':
                need(info[6] == len(config) and row['sha256'] == hashlib.sha256(config).hexdigest(), 'controller-config')
            total += info[6]
    need(type(value['totalBytes']) is int and value['totalBytes'] == total and total <= 8 * 1024 * 1024,
         'controller-total')
    return value


def controller_runtime_data(value, work):
    root = str(work / 'python-controller')
    expected = dict(executable=root + '/bin/python3.14', prefix=root, execPrefix=root,
                    basePrefix=str(Path(CONTROLLER_BASE).parent.parent),
                    baseExecPrefix=str(Path(CONTROLLER_BASE).parent.parent), version=[3, 14, 7],
                    isolated=True, noSite=True, dontWriteBytecode=True, filesystemEncoding='utf-8')
    need(type(value) is dict and value == expected and all(value[key] is True
         for key in ('isolated', 'noSite', 'dontWriteBytecode'))
         and all(type(item) is int for item in value['version']), 'controller-runtime')
    return True


def pairs(rows):
    result = {}
    for key, value in rows:
        need(key not in result, 'duplicate-json-key')
        result[key] = value
    return result


def finite_float(value):
    parsed = float(value)
    need(math.isfinite(parsed), 'nonfinite-json')
    return parsed


def document(raw):
    return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs, parse_float=finite_float,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite-json')))


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def tool_shape_data(info, current_uid, executable):
    # Observation only: never substitutes for admitted identity or its POST.
    return dict(mode=info.st_mode, uid=info.st_uid, gid=info.st_gid,
                nlink=info.st_nlink, size=info.st_size, executableRequired=executable,
                regular=stat.S_ISREG(info.st_mode), ownerAllowed=info.st_uid in (0, current_uid),
                writeProtected=not info.st_mode & 0o022, positiveLinks=info.st_nlink > 0,
                executableAllowed=not executable or bool(info.st_mode & 0o111),
                sizeAllowed=0 < info.st_size <= 256 * 1024 * 1024)


def owner_error_data(error, owner):
    # Closed observation only; never substitutes for an original return.
    if owner is None:
        return dict(available=False, typedFacts=[], chainTruncated=False)
    reasons = {
        'owned command produced incomplete output': 'incomplete-output',
        'owned command output exceeds its bound': 'output-bound',
        'owned command protocol or original ownership is incomplete': 'protocol-or-ownership',
        'owned command failed, timed out, or produced incomplete output': 'command-failed-or-incomplete',
        'owned command cleanup could not be confirmed': 'cleanup-unconfirmed',
        'owned command executable could not be started': 'exec-rejected',
        'owned command was stopped before execution': 'stopped-before-exec',
        'owned command original parent ended': 'parent-ended',
        'owned command original observer ended': 'observer-ended',
        'owned command fence name already exists': 'fence-collision',
    }
    pending, seen, facts = [error], set(), []
    while pending and len(seen) < 16:
        current = pending.pop()
        if current is None or id(current) in seen: continue
        seen.add(id(current))
        if isinstance(current, (owner.ProcessError, owner.ProcessInterrupted)):
            interrupted = isinstance(current, owner.ProcessInterrupted)
            row = dict(kind='interrupted' if interrupted else 'process-error')
            for source, target in (('dispatched', 'dispatched'), ('contained', 'contained'),
                                   ('cleanup_complete', 'cleanupComplete')):
                value = getattr(current, source, None)
                row[target] = value if type(value) is bool else None
            mask = getattr(current, 'owner_failure_mask', None) if not interrupted else None
            # Simultaneous failed predicates, NOT chronological cause or authority.
            row['ownerFailureMask'] = mask if type(mask) is int and 1 <= mask <= 63 else None
            args = current.args
            row['reason'] = (reasons.get(args[0], 'unknown')
                             if len(args) == 1 and type(args[0]) is str else 'unknown')
            facts.append(row)
        pending.extend((current.__context__, current.__cause__))
    return dict(available=True, typedFacts=facts, chainTruncated=bool(pending))


def returned_data(result, argv, cap):
    return (type(result) is subprocess.CompletedProcess and type(result.args) is list
            and result.args == argv and type(result.returncode) is int
            and type(result.stdout) is bytes and type(result.stderr) is bytes
            and len(result.stdout) + len(result.stderr) <= cap)


def commands_data(node, npm, rust_bin, work):
    return (
        [str(node), '--version'], [str(node), str(npm), '--version'],
        [str(rust_bin / 'rustc'), '--version', '--verbose'],
        [str(rust_bin / 'cargo'), '--version', '--verbose'],
        [str(node), str(npm), 'ci', '--ignore-scripts', '--no-audit', '--no-fund',
         '--cache', str(work / 'npm-cache')],
        [str(node), str(npm), 'run', 'build'],
        [str(rust_bin / 'cargo'), 'build', '--locked', '--release', '--jobs', '1',
         '--manifest-path', '../helpers/macos-desktop-image/Cargo.toml', '--lib',
         '--target', TARGET, '--message-format=json-render-diagnostics'],
    )


def artifact_data(raw, checkout, work):
    need(type(raw) is bytes and 0 < len(raw) <= CAPTURE and raw.endswith(b'\n'), 'cargo-output-bound')
    lines = raw.splitlines()
    need(0 < len(lines) <= 16384 and all(0 < len(line) <= 1024 * 1024 for line in lines), 'cargo-line-bound')
    rows = [document(line) for line in lines]
    need(all(type(row) is dict and type(row.get('reason')) is str for row in rows), 'cargo-document')
    finished = [row for row in rows if row['reason'] == 'build-finished']
    need(len(finished) == 1 and type(finished[0].get('success')) is bool
         and finished[0]['success'] and rows[-1] is finished[0], 'cargo-finished')
    facade = checkout / 'desktop/helpers/macos-desktop-image'
    output = work / 'cargo-target' / TARGET / 'release/libmrk_desktop_image.dylib'
    selected = [row for row in rows if row['reason'] == 'compiler-artifact'
                and row.get('manifest_path') == str(facade / 'Cargo.toml')
                and type(row.get('target')) is dict and row['target'].get('name') == 'mrk_desktop_image']
    need(len(selected) == 1, 'cargo-facade-count')
    row = selected[0]
    target, profile = row.get('target'), row.get('profile')
    need(type(target) is dict and type(profile) is dict, 'cargo-target-shape')
    need(target.get('name') == 'mrk_desktop_image' and target.get('kind') == ['cdylib']
         and target.get('crate_types') == ['cdylib'] and target.get('src_path') == str(facade / 'src/lib.rs')
         and profile.get('test') is False and profile.get('debug_assertions') is False
         and row.get('filenames') == [str(output)] and row.get('executable') is None
         and row.get('fresh') is False, 'cargo-real-facade')
    app = [row for row in rows if row['reason'] == 'compiler-artifact'
           and row.get('manifest_path') == str(checkout / 'desktop/src-tauri/Cargo.toml')
           and type(row.get('target')) is dict and row['target'].get('name') == 'mobile_release_desktop']
    need(len(app) == 1 and type(app[0].get('features')) is list, 'cargo-app-count')
    need(len(app[0]['features']) == 3 and all(type(value) is str for value in app[0]['features'])
         and set(app[0]['features']) == {'desktop-shell', 'custom-protocol', 'macos-installed-desktop-image'}
         and app[0].get('profile', {}).get('test') is False, 'cargo-shipping-feature')
    return output


def cleanup_allowed_data(rows, pending, source_post, tools_post):
    return (pending is False and source_post is True and tools_post is True
            and type(rows) is list and len(rows) <= len(ROLES)
            and all(type(row) is dict and row.get('role') == ROLES[index]
                    and row.get('returned') is True and row.get('capturesSettled') is True
                    and type(row.get('returncode')) is int for index, row in enumerate(rows)))


def passed_data(receipt):
    rows = receipt.get('commands')
    return (type(rows) is list and len(rows) == len(ROLES)
            and cleanup_allowed_data(rows, receipt.get('originalPending'), receipt.get('sourcePost'), receipt.get('toolsPost'))
            and all(row['returncode'] == 0 for row in rows)
            and receipt.get('frontendGenerated') is True and receipt.get('facadeArtifactVerified') is True
            and receipt.get('inputOriginalsKnown') is True and receipt.get('toolOriginalsClosed') is True
            and receipt.get('generatedOutputsRetired') is True
            and receipt.get('pythonControllerPrepared') is True and receipt.get('pythonControllerPost') is True
            and receipt.get('pythonControllerRetired') is True
            and all(receipt.get(name) is False for name in ('installedQualified', 'runtimeQualified', 'launched', 'signed'))
            and receipt.get('failure') is None)


def main():
    start = time.monotonic()
    work_end, hard_end = start + 1320, start + 1440  # Same24min, reserve120 inside it.
    checkout = Path('/Users/runner/work/mobile-release-kit/mobile-release-kit')
    work = Path(os.environ['MRK_MACOS_WORK'])
    source = os.environ['GITHUB_SHA']
    need(sys.platform == 'darwin' and sys.maxsize == 2**63 - 1 and sys.flags.isolated and sys.flags.no_site
         and os.getuid() != 0 and os.getuid() == os.geteuid() and os.getgid() == os.getegid()
         and os.uname().machine == 'arm64', 'compile-host')
    need(work.parent == Path('/Users/runner/work/_temp') and re.fullmatch(r'mrk-macos-image-compile\.[A-Za-z0-9_]{8}', work.name)
         and Path(os.environ['GITHUB_WORKSPACE']) == checkout and os.environ['MRK_MACOS_TARGET'] == TARGET
         and re.fullmatch(r'[0-9a-f]{40}', source)
         and os.environ['GITHUB_WORKFLOW_SHA'] == source
         and os.environ['GITHUB_REF'] == 'refs/heads/verify/desktop-macos-image-compile', 'compile-route')
    initial = work.lstat()
    need(stat.S_ISDIR(initial.st_mode) and stat.S_IMODE(initial.st_mode) == 0o700
         and initial.st_uid == os.getuid(), 'compile-original-work')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    tools, outputs, roots, configs = [], {}, [], []
    pending = False
    input_originals_known = True
    controller = None
    owner = None
    receipt = dict(schemaVersion=1, scope='fixed-arm-shipping-image-compile-only', source=source,
                   workflowSource=source, runId=os.environ['GITHUB_RUN_ID'], runAttempt=os.environ['GITHUB_RUN_ATTEMPT'],
                   target=TARGET, commands=[], originalPending=False, sourcePost=False, toolsPost=False,
                   frontendGenerated=False, facadeArtifactVerified=False, facadeArtifactObserved=None, inputOriginalsKnown=True, toolOriginalsClosed=False,
                   generatedOutputsRetired=False, shippingGraphCompiled=False, installedQualified=False,
                   runtimeQualified=False, launched=False, signed=False, failure=None,
                   pythonController=None, pythonControllerObserved=None, pythonControllerRuntime=None,
                   pythonControllerPrepared=False, pythonControllerPost=False, pythonControllerRetired=False)
    failure_status = 1
    stage = 'admission'

    def cut(cleanup=False):
        need(time.monotonic() < (hard_end if cleanup else work_end), 'compile-deadline')

    def root_post():
        now = work.lstat()
        need((now.st_dev, now.st_ino, now.st_mode, now.st_uid, now.st_gid) ==
             (initial.st_dev, initial.st_ino, initial.st_mode, initial.st_uid, initial.st_gid), 'compile-root-changed')

    def read(path, limit, *, expected=None):
        nonlocal input_originals_known
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
                 'compile-file-shape')
            raw = bytearray()
            while len(raw) < before.st_size:
                cut(True)
                block = os.read(fd, min(65536, before.st_size - len(raw)))
                need(bool(block), 'compile-file-short')
                raw.extend(block)
            need(not os.read(fd, 1) and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), 'compile-file-post')
            value = bytes(raw)
            if expected is not None: need(hashlib.sha256(value).hexdigest() == expected, 'compile-source-hash')
            return value, before
        finally:
            try: os.close(fd)  # One consuming close; never retry an uncertain original.
            except OSError:
                input_originals_known = False
                raise

    def publish(name, raw, limit):
        nonlocal input_originals_known
        need(type(raw) is bytes and len(raw) <= limit, 'compile-public-bound')
        cut(True); root_post()
        path = work / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            original = os.fstat(fd)
            need(stat.S_ISREG(original.st_mode) and stat.S_IMODE(original.st_mode) == 0o600
                 and original.st_uid == os.getuid() and original.st_nlink == 1 and original.st_size == 0, 'compile-public-original')
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                cut(True)
                need(stream.write(raw) == len(raw), 'compile-public-short')
                stream.flush(); cut(True); os.fsync(fd); cut(True)
            info = os.fstat(fd)
            need(identity(info)[:6] == identity(original)[:6] and info.st_size == len(raw)
                 and identity(info) == identity(path.lstat()), 'compile-public-post')
            return identity(info)
        finally:
            try: os.close(fd)
            except OSError:
                input_originals_known = False
                raise

    def configs_post():
        for path, original in configs:
            raw, info = read(path, 0)
            need(raw == b'' and identity(info) == original, 'compile-npm-config-changed')

    def controller_post(full=False, cleanup=False):
        nonlocal input_originals_known
        need(controller is not None, 'controller-record')
        root = work / 'python-controller'
        for index, row in enumerate(controller['rows']):
            cut(cleanup); root_post()
            relative = row['path']
            path = root / relative
            expected = tuple(row['identity'])
            if relative in CONTROLLER_DIRS:
                fd = os.open(path, flags | os.O_DIRECTORY)
                try:
                    before = os.fstat(fd)
                    if receipt['failure'] is None:
                        receipt['pythonControllerObserved'] = dict(slot=index, identity=identity(before))
                    need(identity(before) == expected == identity(path.lstat()), 'controller-original-changed')
                    children = {Path(name).name for name in CONTROLLER_DIRS + CONTROLLER_FILES if name
                                and str(Path(name).parent) == (relative or '.')}
                    found = set()
                    with os.scandir(fd) as entries:
                        for entry in entries:
                            cut(cleanup)
                            need(len(found) < len(children) and entry.name in children and entry.name not in found,
                                 'controller-roster')
                            found.add(entry.name)
                    need(found == children, 'controller-roster')
                    need(identity(os.fstat(fd)) == expected == identity(path.lstat()), 'controller-original-changed')
                finally:
                    try: os.close(fd)
                    except BaseException:
                        input_originals_known = False
                        raise
            elif full:
                raw, before = read(path, 1024 * 1024 if relative in CONTROLLER_EXES else 4096 if relative == 'pyvenv.cfg' else 65536,
                                   expected=row['sha256'])
                if receipt['failure'] is None:
                    receipt['pythonControllerObserved'] = dict(slot=index, identity=identity(before))
                need(identity(before) == expected, 'controller-original-changed')
                if relative == 'pyvenv.cfg':
                    need(raw == controller_config_data(work), 'controller-config')
            else:
                before = path.lstat()
                if receipt['failure'] is None:
                    receipt['pythonControllerObserved'] = dict(slot=index, identity=identity(before))
                need(identity(before) == expected, 'controller-original-changed')
        cut(cleanup)
        return True

    def source_post(inventory):
        need(type(inventory) is dict and inventory.get('source') == source and type(inventory.get('files')) is list
             and 0 < len(inventory['files']) < 4096, 'compile-source-inventory')
        seen = set()
        for row in inventory['files']:
            cut(True)
            need(type(row) is dict and set(row) == {'path', 'gitMode', 'blob', 'size', 'sha256'}, 'compile-source-row')
            name = row['path']
            need(type(name) is str and not name.startswith('/') and name not in seen
                 and all(part not in ('', '.', '..') for part in name.split('/'))
                 and row['gitMode'] in ('100644', '100755') and type(row['size']) is int
                 and 0 <= row['size'] <= 32 * 1024 * 1024, 'compile-source-path')
            seen.add(name)
            body, info = read(checkout / name, 32 * 1024 * 1024, expected=row['sha256'])
            need(len(body) == row['size'] and bool(info.st_mode & 0o111) == (row['gitMode'] == '100755')
                 and hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest() == row['blob'], 'compile-source-blob')
        return True

    def tool(path, executable=True):
        fd = os.open(path, flags)
        row = {'path': path, 'fd': fd, 'identity': None, 'sha256': None, 'observedShape': None}
        tools.append(row)
        info = os.fstat(fd)
        row['observedShape'] = tool_shape_data(info, os.getuid(), executable)
        need(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022
             and info.st_nlink > 0 and (not executable or info.st_mode & 0o111)
             and 0 < info.st_size <= 256 * 1024 * 1024, 'compile-tool-shape')
        row['identity'] = identity(info)
        row['sha256'] = tool_hash(row)
        return path

    def tool_hash(row):
        need(row['identity'] == identity(os.fstat(row['fd'])) == identity(row['path'].lstat()), 'compile-tool-changed')
        digest, offset = hashlib.sha256(), 0
        while offset < row['identity'][6]:
            cut(True)
            block = os.pread(row['fd'], min(1024 * 1024, row['identity'][6] - offset), offset)
            need(bool(block), 'compile-tool-short')
            digest.update(block); offset += len(block)
        need(not os.pread(row['fd'], 1, offset) and row['identity'] == identity(os.fstat(row['fd']))
             == identity(row['path'].lstat()), 'compile-tool-post')
        return digest.hexdigest()

    def tools_post(full=False):
        for row in tools:
            need(row['identity'] == identity(os.fstat(row['fd'])) == identity(row['path'].lstat()), 'compile-tool-changed')
            if full: need(row['sha256'] == tool_hash(row), 'compile-tool-hash')
        return True

    def produced_root(name):
        path = checkout / 'desktop' / name
        try: info = path.lstat()
        except FileNotFoundError: return False
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
             and info.st_dev == initial.st_dev, 'compile-generated-root')
        need(all(old != path for old, _ in roots), 'compile-root-replacement')
        roots.append((path, identity(info)[:5]))
        return True

    def absent_frontend(name):
        try: (checkout / 'desktop' / name).lstat()
        except FileNotFoundError: return
        raise ValueError('compile-frontend-already-present')

    def output_hash(path):
        nonlocal input_originals_known
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            receipt['facadeArtifactObserved'] = dict(mode=info.st_mode, uid=info.st_uid, gid=info.st_gid,
                nlink=info.st_nlink, size=info.st_size, regular=stat.S_ISREG(info.st_mode),
                ownerAllowed=info.st_uid == os.getuid(), singleLink=info.st_nlink == 1,
                sizeAllowed=0 < info.st_size <= 256 * 1024 * 1024)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                 and 0 < info.st_size <= 256 * 1024 * 1024, 'compile-artifact-file')
            digest, offset = hashlib.sha256(), 0
            while offset < info.st_size:
                cut(True)
                block = os.read(fd, min(1024 * 1024, info.st_size - offset))
                need(bool(block), 'compile-artifact-short')
                digest.update(block); offset += len(block)
            need(not os.read(fd, 1) and identity(info) == identity(os.fstat(fd)) == identity(path.lstat()), 'compile-artifact-post')
            return dict(bytes=offset, sha256=digest.hexdigest(), identity=identity(info))
        finally:
            try: os.close(fd)
            except OSError:
                input_originals_known = False
                raise

    try:
        binding_raw, binding_original = read(work / 'compile-binding.json', 16384)
        binding = document(binding_raw)
        need(type(binding) is dict and binding == dict(schemaVersion=1, source=source, workflowSource=source,
                            runId=os.environ['GITHUB_RUN_ID'], runAttempt=os.environ['GITHUB_RUN_ATTEMPT'],
                            workDirectory=[initial.st_dev, initial.st_ino, initial.st_uid],
                            frontendAbsentAtAdmission=True, pythonController=binding.get('pythonController')), 'compile-binding')
        controller = controller_record_data(binding['pythonController'], work, identity(initial))
        receipt['pythonController'] = controller
        runtime = dict(executable=sys.executable, prefix=sys.prefix, execPrefix=sys.exec_prefix,
                       basePrefix=sys.base_prefix, baseExecPrefix=sys.base_exec_prefix, version=list(sys.version_info[:3]),
                       isolated=bool(sys.flags.isolated), noSite=bool(sys.flags.no_site),
                       dontWriteBytecode=sys.dont_write_bytecode, filesystemEncoding=sys.getfilesystemencoding())
        receipt['pythonControllerRuntime'] = runtime
        controller_runtime_data(runtime, work)
        need(os.environ.get('MRK_PYTHON') == runtime['executable'], 'controller-runtime')
        controller_post(full=True)
        roots.append((work / 'python-controller', tuple(controller['rows'][0]['identity'][:5])))
        receipt['pythonControllerPrepared'] = True
        inventory_raw, inventory_original = read(work / 'source-inventory.json', SOURCE_LIMIT)
        inventory = document(inventory_raw)
        receipt['sourceInventorySha256'] = hashlib.sha256(inventory_raw).hexdigest()
        receipt['sourceInventoryBytes'] = len(inventory_raw)
        source_post(inventory)
        release = document(read(checkout / 'desktop/macos-installed-inputs/build-release.json', 4096)[0])
        cargo = tomllib.loads(read(checkout / 'desktop/src-tauri/Cargo.toml', 65536)[0].decode())
        tauri = document(read(checkout / 'desktop/src-tauri/tauri.conf.json', 65536)[0])
        need(set(release) == {'schemaVersion', 'packageVersion', 'release'} and type(release['schemaVersion']) is int
             and release['schemaVersion'] == 1 and release['packageVersion'] == cargo['package']['version'] == tauri['version']
             and re.fullmatch(r'macos26-arm64-[a-z0-9](?:[a-z0-9._-]{0,40}[a-z0-9])?', release['release']), 'compile-release-source')
        for name in ('node_modules', 'dist'):
            try: (checkout / 'desktop' / name).lstat()
            except FileNotFoundError: pass
            else: raise ValueError('compile-frontend-already-present')
        for parent in (checkout / 'desktop', *(checkout / 'desktop').parents):
            try: (parent / '.npmrc').lstat()
            except FileNotFoundError: pass
            else: raise ValueError('compile-project-npm-config')
        for name in ('npm-cache', 'compile-home', 'compile-tmp', 'cargo-target'):
            cut(); root_post()
            path = work / name
            path.mkdir(mode=0o700)
            roots.append((path, identity(path.lstat())[:5]))
        for name in ('compile-user.npmrc', 'compile-global.npmrc'):
            cut()
            original = publish(name, b'', 0)
            configs.append((work / name, original))
        node_selected, npm_selected = shutil.which('node'), shutil.which('npm')
        need(node_selected is not None and npm_selected is not None, 'compile-node-unavailable')
        node = tool(Path(node_selected).resolve(strict=True))
        npm = tool(Path(npm_selected).resolve(strict=True), executable=False)
        need(npm == node.parent.parent / 'lib/node_modules/npm/bin/npm-cli.js', 'compile-npm-same-distribution')
        rust_bin = Path('/Users/runner/.rustup/toolchains/1.98.1-aarch64-apple-darwin/bin')
        tool(rust_bin / 'rustc'); tool(rust_bin / 'cargo')
        tool(Path(sys.executable).resolve(strict=True))
        need(tools[-1]['identity'] == tuple(controller['rows'][len(CONTROLLER_DIRS) + 1]['identity'])
             and tools[-1]['sha256'] == controller['baseSha256'], 'controller-source-copy')
        spec = importlib.util.spec_from_file_location('_mrk_shipping_compile_existing_owner', checkout / 'desktop/tools/macos_aqua_qualification.py')
        qualification = importlib.util.module_from_spec(spec); sys.modules[spec.name] = qualification
        spec.loader.exec_module(qualification)
        owner = qualification.load_owner(checkout)
        base = dict(PATH=str(rust_bin) + ':' + str(node.parent) + ':/usr/bin:/bin:/usr/sbin:/sbin', HOME='/Users/runner',
                    CARGO_HOME='/Users/runner/.cargo', RUSTUP_HOME='/Users/runner/.rustup', RUSTC=str(rust_bin / 'rustc'),
                    RUSTUP_TOOLCHAIN=RUST_RELEASE, RUSTUP_AUTO_INSTALL='0', CARGO_INCREMENTAL='0',
                    CARGO_TARGET_DIR=str(work / 'cargo-target'), TMPDIR=str(work / 'compile-tmp'),
                    LANG='C', LC_ALL='C', TZ='UTC', CI='true', DEVELOPER_DIR='/Library/Developer/CommandLineTools',
                    MACOSX_DEPLOYMENT_TARGET='26.0', MRK_MACOS_INSTALL_SOURCE_COMMIT=source, MRK_IMAGE_RELEASE_ID=release['release'])
        npm_env = dict(base, HOME=str(work / 'compile-home'), npm_config_userconfig=str(work / 'compile-user.npmrc'),
                       npm_config_globalconfig=str(work / 'compile-global.npmrc'), npm_config_registry='https://registry.npmjs.org/',
                       npm_config_cache=str(work / 'npm-cache'), npm_config_update_notifier='false')
        argv_rows = commands_data(node, npm, rust_bin, work)
        for index, (role, argv) in enumerate(zip(ROLES, argv_rows, strict=True)):
            stage = role
            cut(); root_post(); need(tools_post(), 'compile-tools-pre'); controller_post()
            if index in (1, 4, 5): configs_post()
            environment = npm_env if index in (1, 4, 5) else base
            cwd = checkout / ('desktop/src-tauri' if index in (2, 3, 6) else 'desktop')
            cap = 4096 if index < 4 else CAPTURE
            if index == 4:
                absent_frontend('node_modules'); absent_frontend('dist')
            elif index == 5:
                absent_frontend('dist')
                for path, original in roots:
                    need(identity(path.lstat())[:5] == original, 'compile-generated-root-changed')
            timeout = min(15 if index < 4 else (300 if index == 4 else 180 if index == 5 else 900), work_end - time.monotonic())
            need(timeout > 0, 'compile-no-work-left')
            pending = True; receipt['originalPending'] = True
            result = owner.run_owned(argv, environ=environment, cwd=cwd, timeout=timeout,
                                     capture=True, text=False, output_limit=cap)
            need(returned_data(result, argv, cap), 'compile-original-return')
            pending = False; receipt['originalPending'] = False
            receipt['commands'].append(dict(role=role, argv=argv, returned=True, capturesSettled=True,
                                            returncode=result.returncode, stdoutBytes=len(result.stdout), stderrBytes=len(result.stderr),
                                            stdoutSha256=hashlib.sha256(result.stdout).hexdigest(), stderrSha256=hashlib.sha256(result.stderr).hexdigest()))
            if result.returncode != 0: failure_status = result.returncode
            if index >= 4:
                outputs[role + '.stdout'] = result.stdout; outputs[role + '.stderr'] = result.stderr
            produced = True
            if index == 4: produced = produced_root('node_modules')
            elif index == 5: produced = produced_root('dist')
            if result.returncode != 0:
                raise ValueError('compile-original-nonzero')
            cut(); need(tools_post(), 'compile-tools-post'); controller_post()
            if index in (1, 4, 5): configs_post()
            need(produced, 'compile-generated-root-missing')
            if index == 0:
                need(result.stdout == b'v24.20.0\n' and not result.stderr, 'compile-node-version')
            elif index == 1:
                need(re.fullmatch(rb'[0-9]+\.[0-9]+\.[0-9]+\n', result.stdout) and not result.stderr, 'compile-npm-version')
            elif index in (2, 3):
                tool_name = 'rustc' if index == 2 else 'cargo'
                lines = result.stdout.decode('utf-8', 'strict').strip().splitlines()
                need(not result.stderr and lines[0].startswith(tool_name + ' ')
                     and [line for line in lines if line.startswith('release:')] == ['release: ' + RUST_RELEASE]
                     and [line for line in lines if line.startswith('host:')] == ['host: ' + TARGET], 'compile-rust-version')
                if index == 2: need([line for line in lines if line.startswith('commit-hash:')] == ['commit-hash: ' + RUST_COMMIT], 'compile-rust-commit')
            elif index == 5:
                body, info = read(checkout / 'desktop/dist/index.html', 1024 * 1024)
                need(body and info.st_uid == os.getuid(), 'compile-genuine-frontend')
                receipt['frontendGenerated'] = True
            elif index == 6:
                output = artifact_data(result.stdout, checkout, work)
                receipt['facadeArtifact'] = output_hash(output)
                receipt['facadeArtifactVerified'] = True
        receipt['release'] = release
    except BaseException as error:
        receipt['failure'] = dict(stage=stage, kind=type(error).__name__)
        if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str and error.args[0] in CONTROLLER_REASONS + ARTIFACT_REASONS:
            receipt['failure']['condition'] = error.args[0]
        try:
            receipt['failure']['ownerDiagnostic'] = owner_error_data(error, owner)
        except BaseException:
            # Diagnostic failure cannot replace the original error or settle pending work.
            receipt['failure']['ownerDiagnostic'] = dict(available=False)
    finally:
        receipt['originalPending'] = pending
        try:
            cut(True); root_post()
            if not pending and input_originals_known:
                if 'inventory' in locals():
                    current, current_info = read(work / 'source-inventory.json', SOURCE_LIMIT, expected=receipt['sourceInventorySha256'])
                    need(current == inventory_raw and identity(current_info) == identity(inventory_original), 'compile-source-inventory-changed')
                    current, current_info = read(work / 'compile-binding.json', 16384)
                    need(current == binding_raw and identity(current_info) == identity(binding_original), 'compile-binding-changed')
                    receipt['sourcePost'] = source_post(inventory)
                receipt['toolsPost'] = tools_post(full=True)
                configs_post()
                if controller is not None:
                    receipt['pythonControllerPost'] = controller_post(full=True, cleanup=True)
        except BaseException as error:
            if receipt['failure'] is None:
                receipt['failure'] = dict(stage='source-tool-post', kind=type(error).__name__)
                if type(error) is ValueError and len(error.args) == 1 and error.args[0] in CONTROLLER_REASONS:
                    receipt['failure']['condition'] = error.args[0]
        close_ok = True
        # Unknown owner return does not grant retirement of tool originals or output trees.
        if not pending and input_originals_known:
            for row in reversed(tools):
                fd, row['fd'] = row['fd'], None
                try: os.close(fd)
                except OSError: close_ok = False
            receipt['toolOriginalsClosed'] = close_ok
        if (cleanup_allowed_data(receipt['commands'], pending, receipt['sourcePost'], receipt['toolsPost'])
                and close_ok and input_originals_known
                and receipt['pythonControllerPrepared'] and receipt['pythonControllerPost']):
            try:
                cut(True); root_post()
                need(shutil.rmtree.avoids_symlink_attacks, 'compile-safe-cleanup-unavailable')
                for path, before in reversed(configs):
                    cut(True); root_post()
                    need(identity(path.lstat()) == before, 'compile-npm-config-changed')
                    path.unlink()
                    try: path.lstat()
                    except FileNotFoundError: pass
                    else: raise ValueError('compile-cleanup-not-absent')
                for path, before in reversed(roots):
                    cut(True); root_post()
                    info = path.lstat()
                    need(identity(info)[:5] == before and stat.S_ISDIR(info.st_mode)
                         and info.st_uid == os.getuid() and info.st_dev == initial.st_dev, 'compile-cleanup-original')
                    shutil.rmtree(path)
                    try: path.lstat()
                    except FileNotFoundError: pass
                    else: raise ValueError('compile-cleanup-not-absent')
                    if path == work / 'python-controller': receipt['pythonControllerRetired'] = True
                cut(True)
                receipt['generatedOutputsRetired'] = True
            except BaseException as error:
                if receipt['failure'] is None: receipt['failure'] = dict(stage='generated-cleanup', kind=type(error).__name__)
        if not receipt['toolOriginalsClosed'] and receipt['failure'] is None:
            receipt['failure'] = dict(stage='tool-close', kind='UnknownOriginal')
        receipt['toolOriginals'] = [dict(path=str(row['path']), identity=row['identity'], sha256=row['sha256'],
                                        observedShape=row['observedShape']) for row in tools]
        receipt['inputOriginalsKnown'] = input_originals_known
        # Local captured compiler originals only; never included in the artifact.
        try:
            for name, raw in outputs.items(): publish(name, raw, CAPTURE)
        except BaseException as error:
            if receipt['failure'] is None: receipt['failure'] = dict(stage='public-capture', kind=type(error).__name__)
        receipt['inputOriginalsKnown'] = input_originals_known
        receipt['shippingGraphCompiled'] = passed_data(receipt)
        try:
            publish('compile-receipt.json', (json.dumps(compile_public_data(receipt, source, os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']), sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii'), 65536)
            cut(True); root_post()
        except BaseException:
            # Never replace an original child failure or retry a partial public file.
            raise SystemExit(failure_status)
    if not receipt['shippingGraphCompiled']: raise SystemExit(failure_status)


main()
PY_SHIPPING_IMAGE_COMPILE
