#!/usr/bin/env python3
"""Four fixed native archive calls; no installation, signing or app build."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

REF = 'refs/heads/verify/desktop-macos-package-format-diagnostic'
SCRIPT = 'desktop/tools/macos_package_format_diagnostic.py'
WORKFLOW = '.github/workflows/desktop-macos-package-format-diagnostic.yml'
TARGET = 'x86_64-apple-darwin'
SCRATCH_PARENT = Path('/Users/runner/work/_temp')
TOOLS = ('/usr/bin/pkgbuild', '/usr/bin/bsdtar', '/usr/bin/xar', '/usr/bin/productbuild')
FILE_LIMIT = 4 * 1024 * 1024
TOTAL_LIMIT = 16 * 1024 * 1024
CORE = ('__init__.py', 'errors.py', 'owned_process.py', '_command_process.py',
        '_native_process.py', 'cancellation.py', '_lifetime_evidence.py', '_store_lane_contract.py')
SOURCES = (SCRIPT, WORKFLOW, 'desktop/tools/stage_macos_installed.py',
           'desktop/tools/macos_aqua_qualification.py',
           'desktop/macos-installed-inputs/build-release.json',
           'desktop/macos-installed-inputs/build-release-intel.json',
           'desktop/macos-installed-inputs/Distribution.xml',
           'desktop/macos-installed-inputs/InstallerReadMe.html') + tuple('src/mobile_release/' + name for name in CORE)


class Refused(Exception):
    pass


def need(condition):
    if not condition:
        raise Refused('fixed-format-diagnostic-refused')


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory(info):
    need(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022)
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def context(environment, script, host, uid, euid):
    source = environment.get('GITHUB_SHA', '')
    root = Path('/Users/runner/work/mobile-release-kit/mobile-release-kit')
    fixed = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': REF,
             'GITHUB_REPOSITORY': 'Apdelrahman1911/mobile-release-kit',
             'GITHUB_WORKSPACE': str(root), 'GITHUB_WORKFLOW_SHA': source,
             'GITHUB_WORKFLOW_REF': 'Apdelrahman1911/mobile-release-kit/' + WORKFLOW + '@' + REF,
             'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'macOS', 'RUNNER_ARCH': 'X64',
             'RUNNER_TEMP': str(SCRATCH_PARENT)}
    need(all(environment.get(k) == value for k, value in fixed.items())
         and re.fullmatch('[0-9a-f]{40}', source) and source != '0' * 40
         and Path(script).absolute() == root / SCRIPT and host.sysname == 'Darwin'
         and host.machine == 'x86_64' and type(uid) is int and uid > 0 and uid == euid)
    ids = [environment.get(k, '') for k in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')]
    need(all(re.fullmatch('[1-9][0-9]{0,15}', value) and int(value) <= 9007199254740991 for value in ids))
    return root, {'schemaVersion': 1, 'kind': 'unsigned-package-format-diagnostic',
        'source': source, 'workflowSource': source, 'runId': ids[0], 'runAttempt': ids[1],
        'target': TARGET, 'diagnosticOnly': True, 'productReady': False,
        'signingQualified': False, 'notaryQualified': False, 'installationQualified': False}


class Held:
    """Small original-file ledger; closing never retries an uncertain descriptor."""
    def __init__(self, deadline, anchor=None, diagnostics=None):
        self.deadline, self.files, self.parents, self.anchor = deadline, [], {}, anchor
        self.diagnostics = diagnostics
        self.directories, self.scratch = [], None

    def note(self, check, facts, role=None):
        if self.diagnostics is not None:
            self.diagnostics.update(setupCheck=check, setupFacts=facts, setupRole=role)

    def clock(self):
        need(time.monotonic() < self.deadline)

    def add_directory(self, path, uid, gid, *, role):
        """Acquire one absolute chain; only the final parent has account ownership."""
        need(path.is_absolute() and not any(part in ('.', '..') for part in path.parts) and not self.directories)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        for number, part in enumerate(path.parts):
            self.clock(); need(len(self.directories) < 16)
            parent = self.directories[-1] if self.directories else None
            named = Path('/') if parent is None else parent['path'] / part
            self.note('directory-open', {}, role)
            fd = os.open('/', flags) if parent is None else os.open(part, flags, dir_fd=parent['fd'])
            row = {'path': named, 'fd': fd, 'parent': parent, 'name': None if parent is None else part,
                   'retired': False}
            self.directories.append(row)  # Custody precedes fallible fstat/metadata checks.
            self.note('directory-shape', None, role)
            info = os.fstat(fd)
            self.note('directory-shape', {'directory': stat.S_ISDIR(info.st_mode),
                'ownerMatched': info.st_uid == uid, 'groupMatched': info.st_gid == gid,
                'notGroupOrWorldWritable': not bool(info.st_mode & 0o022)}, role)
            row['identity'] = directory(info)
            observed = named.lstat() if parent is None else os.stat(part, dir_fd=parent['fd'], follow_symlinks=False)
            need(directory(observed) == row['identity'])
            if number == len(path.parts) - 1:
                need(info.st_uid == uid and info.st_gid == gid)
            self.post()
        return self.directories[-1]

    def create_scratch(self, parent, uid, gid):
        self.clock(); self.post(); need(parent is self.directories[-1] and self.scratch is None)
        name = 'mrk-unsigned-format-' + os.urandom(16).hex()
        self.note('scratch-create', {}, 'scratch-root')
        os.mkdir(name, 0o700, dir_fd=parent['fd'])  # Exclusive: collision never retries/adopts.
        row = {'path': parent['path'] / name, 'parent': parent, 'name': name,
               'fd': None, 'retired': False, 'proven': False}
        self.scratch = row  # Record the fresh name immediately; uncertain acquisition preserves it.
        self.note('directory-open', {}, 'scratch-root')
        row['fd'] = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent['fd'])
        self.directories.append(row)
        self.note('directory-shape', None, 'scratch-root')
        info = os.fstat(row['fd'])
        self.note('directory-shape', {'directory': stat.S_ISDIR(info.st_mode),
            'ownerMatched': info.st_uid == uid, 'groupMatched': info.st_gid == gid,
            'privateMode': stat.S_IMODE(info.st_mode) == 0o700}, 'scratch-root')
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and info.st_gid == gid
             and stat.S_IMODE(info.st_mode) == 0o700)
        row['identity'] = directory(info)
        need(directory(os.stat(name, dir_fd=parent['fd'], follow_symlinks=False)) == row['identity'])
        self.post(); row['proven'] = True
        return row['path']

    def retire_empty_scratch(self):
        row = self.scratch
        need(row is not None and row['proven'] and not row['retired'])
        self.clock(); self.post(); need(not os.listdir(row['fd']))
        os.rmdir(row['name'], dir_fd=row['parent']['fd'])
        row['retired'] = True
        self.post()

    def add(self, path, limit, uid, *, role=None):
        self.clock()
        need(len(self.files) < 32)
        # Pin every named ancestor. No followed directory is silently adopted.
        parents = list(path.parents)
        if self.anchor is not None:
            need(self.anchor in parents)
            parents = parents[:parents.index(self.anchor) + 1]
        for parent in reversed(parents):
            if parent not in self.parents:
                self.note('ancestor-shape', None, role)
                info = parent.lstat()
                self.note('ancestor-shape', {'directory': stat.S_ISDIR(info.st_mode),
                    'notGroupOrWorldWritable': not bool(info.st_mode & 0o022)}, role)
                self.parents[parent] = directory(info)
        self.note('file-open', {}, role)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        row = {'path': path, 'fd': fd, 'limit': limit, 'role': role}
        self.files.append(row)
        self.note('file-shape', None, role)
        info = os.fstat(fd)
        self.note('file-shape', {'regular': stat.S_ISREG(info.st_mode), 'ownerMatched': info.st_uid == uid,
            'singleLink': info.st_nlink == 1, 'notGroupOrWorldWritable': not bool(info.st_mode & 0o022),
            'boundedSize': 0 <= info.st_size <= limit}, role)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
             and not info.st_mode & 0o022 and 0 <= info.st_size <= limit)
        row['identity'] = identity(info)
        body = self.read(row)
        row['sha256'] = hashlib.sha256(body).hexdigest()
        return body

    def read(self, row):
        self.note('file-read', {}, row['role'])
        self.clock()
        need(identity(os.fstat(row['fd'])) == row['identity'] == identity(row['path'].lstat()))
        body = bytearray()
        while len(body) < row['identity'][6]:
            self.clock()
            block = os.pread(row['fd'], min(65536, row['identity'][6] - len(body)), len(body))
            need(bool(block)); body.extend(block)
        need(not os.pread(row['fd'], 1, len(body))
             and identity(os.fstat(row['fd'])) == row['identity'] == identity(row['path'].lstat()))
        return bytes(body)

    def post(self):
        for row in self.directories:
            self.clock()
            need(directory(os.fstat(row['fd'])) == row['identity'])
            parent = row['parent']
            if row['retired']:
                try:
                    os.stat(row['name'], dir_fd=parent['fd'], follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    need(False)
            else:
                observed = row['path'].lstat() if parent is None else os.stat(
                    row['name'], dir_fd=parent['fd'], follow_symlinks=False)
                need(directory(observed) == row['identity'])
        for path, before in self.parents.items():
            self.note('ancestor-post', None)
            self.clock()
            info = path.lstat()
            self.note('ancestor-post', {'directory': stat.S_ISDIR(info.st_mode),
                'notGroupOrWorldWritable': not bool(info.st_mode & 0o022)})
            need(directory(info) == before)
        for row in self.files:
            need(hashlib.sha256(self.read(row)).hexdigest() == row['sha256'])

    def close(self):
        complete = True
        for row in reversed(self.files):
            fd, row['fd'] = row['fd'], None
            try:
                os.close(fd)
            except BaseException:
                complete = False
        for row in reversed(self.directories):
            fd, row['fd'] = row['fd'], None
            try:
                os.close(fd)
            except BaseException:
                complete = False
        return complete


def load(name, path, body):
    need(name not in sys.modules)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # Dataclass annotation resolution needs its original module.
    try:
        exec(compile(body, str(path), 'exec'), module.__dict__)
    except BaseException:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


def snapshot(root, deadline):
    """Bounded no-link inventory of this fresh task-only fixture, never an extractor."""
    rows, pending, total = {}, [root], 0
    while pending:
        need(time.monotonic() < deadline and len(rows) + len(pending) <= 64)
        path = pending.pop(); info = path.lstat()
        need(info.st_uid == os.getuid() and not info.st_mode & 0o022)
        if stat.S_ISDIR(info.st_mode):
            rows[path] = ('directory', directory(info), None)
            with os.scandir(path) as entries:
                for entry in entries:
                    need(len(rows) + len(pending) < 64)
                    pending.append(path / entry.name)
        else:
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= FILE_LIMIT)
            total += info.st_size; need(total <= TOTAL_LIMIT)
            held = Held(deadline, root)
            try:
                body = held.add(path, FILE_LIMIT, os.getuid())
                rows[path] = ('file', identity(info), hashlib.sha256(body).hexdigest())
                need(identity(path.lstat()) == identity(info))
            finally:
                need(held.close())
    return rows


def unchanged(previous, current):
    need(all(current.get(path) == row for path, row in previous.items()))


def retire(root, rows, deadline):
    need(snapshot(root, deadline) == rows)
    # The genuine stager seals nested fixture directories0555. Only after
    # original-child finality and exact inventory may this task make its own
    # proven directories owner-writable for deletion. Never chmod an ancestor.
    for path in sorted(rows, key=lambda p: len(p.parts)):
        kind, before, _ = rows[path]
        if kind != 'directory' or before[2] & stat.S_IWUSR:
            continue
        need(time.monotonic() < deadline and (path == root or root in path.parents))
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            need(directory(os.fstat(fd)) == before == directory(path.lstat())
                 and before[3] == os.getuid())
            os.fchmod(fd, stat.S_IMODE(before[2]) | stat.S_IWUSR)
            after = (before[0], before[1], before[2] | stat.S_IWUSR, before[3], before[4])
            need(directory(os.fstat(fd)) == after == directory(path.lstat()))
            rows[path] = (kind, after, None)
        finally:
            os.close(fd)  # Unknown close refuses retirement; no retry.
    for path in sorted(rows, key=lambda p: len(p.parts), reverse=True):
        need(time.monotonic() < deadline)
        kind, before, _ = rows[path]
        need((directory(path.lstat()) if kind == 'directory' else identity(path.lstat())) == before)
        if kind == 'file':
            path.unlink()
        else:
            path.rmdir()


def recipe(stager, root):
    version = stager.source_build_selection(TARGET).package_version
    need(re.fullmatch('[0-9]+(?:\\.[0-9]+){1,3}', version))
    return (
        [TOOLS[0], '--nopayload', '--scripts', str(root / 'scripts'), '--identifier',
         'dev.mobile-release-kit.desktop.installed', '--version', version, '--install-location', '/',
         '--ownership', 'recommended', str(root / 'original.pkg')],
        [TOOLS[1], '-c', '-z', '-f', str(root / 'parts/Scripts'), '--format=odc', '--uid=0', '--gid=0',
         '--no-acls', '--no-xattrs', '--no-fflags', '--no-mac-metadata', '.'],
        [TOOLS[2], '-c', '-f', str(root / 'component/MobileReleaseKit.pkg'), '--compression=none', 'PackageInfo', 'Scripts'],
        [TOOLS[3], '--distribution', str(root / 'presentation/Distribution'), '--package-path', str(root / 'component'),
         '--resources', str(root / 'presentation/resources'), str(root / 'product/MobileReleaseKit.pkg')])


def package_failure(stager, report, error):
    """Only declared package reasons; child captures and exception text stay private."""
    report['packageReason'] = None
    if type(error) is not stager.Refused:
        return
    values = BaseException.args.__get__(error)
    if (len(values) == 1 and type(values[0]) is str
            and (values[0] in stager.PACKAGE_REFUSALS or values[0] in stager.INSTALL_PRODUCT_AUDIT_REASONS)):
        report['packageReason'] = values[0]


def run_probe(stager, owner, root, held, report, work_end, hard_end):
    calls, known = report['calls'], True
    report.update({'auditPassed': False, 'auditReason': None, 'packageReason': None, 'stage': 'source-input', 'scratchRetired': False})
    tree = snapshot(root, hard_end)
    environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(root / 'home'),
        'TMPDIR': str(root / 'tmp'), 'LC_ALL': 'C', 'TZ': 'UTC', 'COPYFILE_DISABLE': '1',
        'DEVELOPER_DIR': '/Library/Developer/CommandLineTools', 'PYTHONDONTWRITEBYTECODE': '1'}
    def adopt():
        nonlocal tree
        current = snapshot(root, hard_end); unchanged(tree, current); tree = current
    def call(argv, cwd):
        nonlocal known
        need(len(calls) < 4 and argv[0] == TOOLS[len(calls)])
        held.post(); need(snapshot(root, hard_end) == tree)
        remaining = int(work_end - time.monotonic()) - 3
        need(remaining >= 1)
        row = {'role': ('pkgbuild', 'tar', 'xar', 'productbuild')[len(calls)],
               'entered': True, 'returned': False, 'known': False, 'returncode': None}
        report['stage'] = row['role']
        calls.append(row); known = False
        result = owner.run_owned(argv, environ=environment, cwd=cwd, timeout=min(30, remaining),
                                 capture=True, text=False, output_limit=65536)
        need(type(result.returncode) is int and type(result.stdout) is bytes and type(result.stderr) is bytes
             and len(result.stdout) + len(result.stderr) <= 65536)
        known = True; row.update({'returned': True, 'known': True, 'returncode': result.returncode})
        held.post(); adopt(); need(result.returncode == 0)
    try:
        for name in ('home', 'tmp', 'component', 'product'):
            (root / name).mkdir(mode=0o700)
        report['stage'] = 'source-input'
        stager.package_format_input_command(argparse.Namespace(output=root / 'scripts'))
        adopt(); argv = recipe(stager, root)
        call(argv[0], root)
        report['stage'] = 'original-prepare'
        stager.prepare_package_command(argparse.Namespace(target=TARGET, fixture=False, scripts=root / 'scripts',
            package=root / 'original.pkg', output=root / 'parts'))
        adopt(); call(argv[1], root / 'scripts'); call(argv[2], root / 'parts')
        args = argparse.Namespace(target=TARGET, fixture=False, scripts=root / 'scripts',
            original_package=root / 'original.pkg', package=root / 'component/MobileReleaseKit.pkg')
        report['stage'] = 'component-audit'
        stager.audit_command(args)
        report['stage'] = 'product-prepare'
        stager.prepare_install_product_command(argparse.Namespace(target=TARGET, output=root / 'presentation'))
        adopt(); call(argv[3], root)
        args.package = root / 'product/MobileReleaseKit.pkg'
        report['product'] = {'bytes': tree[args.package][1][6], 'sha256': tree[args.package][2]}
        report['stage'] = 'product-audit'
        stager.audit_install_product_command(args)
        report['auditPassed'] = True
    except stager.Refused as error:
        package_failure(stager, report, error)
        values = BaseException.args.__get__(error)
        if (report.get('stage') == 'product-audit' and type(error) is stager.Refused and len(values) == 1
                and type(values[0]) is str and values[0] in stager.INSTALL_PRODUCT_AUDIT_REASONS):
            report['auditReason'] = values[0]
        report['failed'] = True
    except BaseException:
        report['failed'] = True  # Never render an arbitrary exception or child capture.
    finally:
        report['originalsKnown'] = known
        try:
            held.post(); report['sourcePost'] = True
        except BaseException:
            report['sourcePost'] = False
        if known:
            try:
                current = snapshot(root, hard_end); unchanged(tree, current)
                retire(root, current, hard_end); report['scratchRetired'] = True
            except BaseException:
                report['scratchRetired'] = False


def setup_stage(report, stage, role=None):
    report.update(setupStage=stage, setupRole=role, setupCheck=None, setupFacts=None)


def setup_failure(report, error):
    kinds = {Refused: 'Refused', ImportError: 'ImportError', ModuleNotFoundError: 'ImportError',
             NameError: 'NameError', AttributeError: 'AttributeError', TypeError: 'TypeError'}
    kind, number = kinds.get(type(error), 'other'), None
    if isinstance(error, OSError):
        kind = 'OSError'
        candidate = OSError.errno.__get__(error)
        if type(candidate) is int and candidate in (1, 2, 5, 9, 13, 20, 21, 22, 24, 28, 40, 60, 62):
            number = candidate
    report.update(setupExceptionClass=kind, setupErrno=number)


def main():
    start = time.monotonic(); work_end, hard_end = start + 180, start + 195
    report = {'diagnosticOnly': True, 'productReady': False, 'failed': True, 'calls': []}
    held = Held(hard_end, diagnostics=report)
    try:
        setup_stage(report, 'context')
        checkout, binding = context(os.environ, __file__, os.uname(), os.getuid(), os.geteuid())
        report.update(binding); report['failed'] = False
        sources = {}
        for name in SOURCES:
            setup_stage(report, 'source-read', name)
            sources[name] = held.add(checkout / name, 2 * 1024 * 1024, os.getuid(), role=name)
        need(all(sources.values()))
        setup_stage(report, 'stager-load')
        stager = load('mrk_format_stager', checkout / SOURCES[2], sources[SOURCES[2]])
        setup_stage(report, 'qualification-load')
        qualification = load('mrk_format_qualification', checkout / SOURCES[3], sources[SOURCES[3]])
        setup_stage(report, 'owner-load')
        owner = qualification.load_owner(checkout)
        for tool in TOOLS:
            setup_stage(report, 'tool-read', tool)
            held.add(Path(tool), 16 * 1024 * 1024, 0, role=tool)
        setup_stage(report, 'source-post')
        held.post()
        report['sourceSha256'] = {name: hashlib.sha256(body).hexdigest() for name, body in sources.items()}
        report['toolSha256'] = {str(row['path']): row['sha256'] for row in held.files if str(row['path']) in TOOLS}
        setup_stage(report, 'scratch-create')
        parent = held.add_directory(SCRATCH_PARENT, os.getuid(), os.getgid(), role='scratch-parent')
        report['scratchRetired'] = False
        root = held.create_scratch(parent, os.getuid(), os.getgid())
        setup_stage(report, 'probe')
        run_probe(stager, owner, root, held, report, work_end, hard_end)
        if report.get('scratchRetired') is True:
            held.scratch['retired'] = True
        held.post()
    except BaseException as error:
        report['failed'] = True
        setup_failure(report, error)
    finally:
        if held.scratch is not None and report.get('setupStage') == 'scratch-create':
            try:
                held.retire_empty_scratch(); report['scratchRetired'] = True
            except BaseException:
                report['scratchRetired'] = False
        report['sourceClosesKnown'] = held.close()
    report['diagnosticComplete'] = (report.get('sourcePost') is True and report['sourceClosesKnown']
        and report.get('originalsKnown') is True and report.get('scratchRetired') is True)
    report['passed'] = report['diagnosticComplete'] and report.get('auditPassed') is True and not report['failed']
    body = json.dumps(report, sort_keys=True, separators=(',', ':'))
    need(body.isascii() and len(body) <= 16384)
    print(body)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
