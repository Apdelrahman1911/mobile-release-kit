"""Fixed synthetic HFS DATA parser reproduction; no install/sign/release."""
import ast
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import resource
import stat
import subprocess
import sys
import time
import types
from xml.parsers.expat import ExpatError

ROOT = Path('/Users/runner/work/mobile-release-kit/mobile-release-kit')
PARENT = Path('/Users/runner/work/_temp')
REF = 'refs/heads/verify/desktop-macos-hfs-parser-probe'
WORKFLOW = 'Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-hfs-parser-probe.yml@' + REF
PUBLIC = 'hfs-parser-public.json'
READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
LIMIT = 16 * 1024 * 1024
CAPTURE = 65536
NAMES = {'Install.pkg': b'not an executable package\n', 'producer.json': b'{}\n', 'producer.sig': b'not a signature\n'}
REASONS = ('distribution-attach-original', 'distribution-attach-plist', 'distribution-attach-entity',
           'distribution-attach-mount', 'distribution-attach-single-mount', 'distribution-package-name',
           'distribution-three-file-roster', 'distribution-original-byte-mode')
SOURCE_PINS = {
    'desktop/tools/macos_xcode_host_preparation.py': (96477, 'd03cfd5c200564efd71050548ebac85b4f9b56fd3619027ec35ce6a1528e5376'),
    'desktop/tools/macos_android_helper_package.py': (533030, '946327b46109dbe5bd0aa8464724e4483e84127a010f7b853dc98f9fdfc4dce0'),
    'desktop/macos-installed-inputs/build-release.json': (95, '521cdb6880415e7f2ac7ef1ebb86d4e5ec9d341dabf7f77e70fc8dc2883c4512'),
    'desktop/tools/macos_e2_native_fixture.py': (390498, 'e4ac0883d7a077d59cc065e3467b4052a47476838f7d0a98cc0e17caaee892a8'),
    'desktop/tools/macos_aqua_qualification.py': (464005, 'f0ba092245e7d7772a8ac02b837f32c3b718139a76f49a3d775404a92c627bbc'),
    'desktop/tools/stage_macos_installed.py': (373915, 'be9abea2b55c65dfb5161fc4d91da58dc8cf5a541af036894dea819e5daa865b'),
    'src/mobile_release/__init__.py': (144, '557bcb0cdcf7f7ef329f04f82cf388c746bb73eba34857b97782a8bcf2e596b2'),
    'src/mobile_release/owned_process.py': (9127, 'ba23e4c65a916c297190c028bd5fd934723ef496105a46ec45c2a2e4b2f22b59'),
    'src/mobile_release/_command_process.py': (177438, 'ad1b7b7140d219674efd326ec529315fdf5a9fd55701a069d7f930a86e702a43'),
    'src/mobile_release/_native_process.py': (62175, '70c380adde3c2bc06a0985761f0f877355bb56ef09ad506440da93fd4e4ba3b4'),
    'src/mobile_release/cancellation.py': (32351, 'eff29612208b2d6d81afa5638fa998778b17f39107357bb7a2f954facdc2628a'),
    'src/mobile_release/errors.py': (749, '26427cedbd05945c1a869af20228f9a04fe1e30d950a2dc246dd0795708a0853'),
    'src/mobile_release/_lifetime_evidence.py': (19514, 'fcac01b5fefc60927cc6c1ebb4d14bb77df0de964c9965900313c573da92826d'),
    'src/mobile_release/_store_lane_contract.py': (9500, '8726cf9bdb053b3d7f30eb9c8307c18239dc518476b2f895ef1610efa65e040e'),
    'src/mobile_release/_store_lane_evidence.py': (17638, 'bcea0084032ffbd43c15f5682f456965aff812e5007d3211a5afe605fc4d5872'),
}


INTERPRETER_REFUSALS = ('selected-interpreter-shape',
    'actual-interpreter-shape', 'supported-interpreter-version', 'interpreter-version-shape',
    'interpreter-isolation', 'interpreter-no-site', 'interpreter-no-bytecode')


class Refused(Exception):
    pass


def need(value):
    if not value:
        raise Refused()


def interpreter_need(value, reason):
    if not value:
        raise Refused(reason)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def context(environment):
    target = environment.get('MRK_HFS_TARGET')
    hosts = {'aarch64-apple-darwin': ('arm64', 'ARM64'), 'x86_64-apple-darwin': ('x86_64', 'X64')}
    source = environment.get('GITHUB_SHA', '')
    need(target in hosts and re.fullmatch('[0-9a-f]{40}', source) is not None and source != '0' * 40)
    expected = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': REF,
        'GITHUB_JOB': 'hfs-parser', 'MRK_PUSH_EVENT_AFTER': source, 'GITHUB_REPOSITORY': 'Apdelrahman1911/mobile-release-kit',
        'GITHUB_WORKSPACE': str(ROOT), 'GITHUB_WORKFLOW_REF': WORKFLOW, 'GITHUB_WORKFLOW_SHA': source,
        'RUNNER_TEMP': str(PARENT), 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'macOS', 'RUNNER_ARCH': hosts[target][1]}
    need(all(environment.get(k) == v for k, v in expected.items()) and sys.platform == 'darwin'
         and os.uname().machine == hosts[target][0] and os.getuid() > 0 and os.getuid() == os.geteuid()
         and os.getgid() == os.getegid() and Path.cwd() == ROOT
         and Path(__file__).absolute() == ROOT / 'desktop/tools/macos_hfs_readonly_parser_probe.py')
    ids = [environment.get(k, '') for k in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')]
    need(all(re.fullmatch('[1-9][0-9]{0,19}', v) is not None for v in ids))
    interpreter = environment.get('MRK_HFS_PYTHON', '')
    interpreter_need(type(interpreter) is str and interpreter.startswith('/') and len(interpreter) <= 4096,
         'selected-interpreter-shape')
    interpreter_need(type(sys.executable) is str and sys.executable.startswith('/') and len(sys.executable) <= 4096,
         'actual-interpreter-shape')
    interpreter_need(sys.implementation.name == 'cpython' and sys.version_info >= (3, 11), 'supported-interpreter-version')
    interpreter_need(all(type(value) is int and 0 <= value <= 255 for value in sys.version_info[:3]), 'interpreter-version-shape')
    interpreter_need(sys.flags.isolated, 'interpreter-isolation')
    interpreter_need(sys.flags.no_site, 'interpreter-no-site')
    interpreter_need(sys.dont_write_bytecode, 'interpreter-no-bytecode')
    expected_sha = environment.get('MRK_HFS_SOURCE_SHA256', '')
    need(re.fullmatch('[0-9a-f]{64}', expected_sha) is not None)
    return dict(source=source, workflowSource=source, runId=ids[0], runAttempt=ids[1], target=target,
                observerSourceSha256=expected_sha,
                python={'version': list(sys.version_info[:3]), 'cpython': True, 'supported': True,
                    'isolated': bool(sys.flags.isolated), 'noSite': bool(sys.flags.no_site),
                    'noBytecode': bool(sys.dont_write_bytecode), 'cachePrefixNone': sys.pycache_prefix is None,
                    'selectedExecutableSameSpelling': interpreter == sys.executable})


def failure_projection(source):
    names = {'original_failure', 'need', 'Refused'}
    nodes = [n for n in ast.parse(source).body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names]
    need(len(nodes) == len(names))
    namespace = {'json': json, 're': re, 'Path': Path}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(ROOT / 'desktop/tools/macos_android_helper_package.py'), 'exec'), namespace)
    return namespace['original_failure']


def module(body, name, filename):
    value = types.ModuleType(name)
    value.__file__ = str(filename)
    sys.modules[name] = value
    exec(compile(body, str(filename), 'exec'), vars(value))
    return value


def original_class(source):
    tree = ast.parse(source)
    names = {'Originals', 'signature', 'need', 'Refused', 'READ_FLAGS'}
    nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names
        or isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id in names]
    need(len(nodes) == len(names))
    namespace = {'os': os, 'stat': stat, 'Path': Path}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(ROOT / 'desktop/tools/macos_e2_native_fixture.py'), 'exec'), namespace)
    return namespace['Originals'], namespace['signature'], namespace['Refused']


def parser_reason(error, stager):
    if type(error) is stager.Refused:
        values = BaseException.args.__get__(error)
        if type(values) is tuple and len(values) == 1 and type(values[0]) is str and values[0] in REASONS:
            return values[0]
    return 'unclassified'


def attach_shape_data(body, stderr, code, mountpoint):
    """Finite diagnostic only; never mounted-object custody or parser authority."""
    result = {'returnZero': type(code) is int and code == 0,
        'stdoutBytes': min(len(body), CAPTURE + 1) if type(body) is bytes else None,
        'stderrEmpty': type(stderr) is bytes and not stderr,
        'stdoutBounded': type(body) is bytes and 0 < len(body) <= CAPTURE,
        'parsed': False, 'rows': []}
    if not result['stdoutBounded']:
        return result
    result.update(encoding='binary' if body.startswith(b'bplist00') else
        'xml' if body.lstrip().startswith((b'<?xml', b'<plist')) else 'other',
        containsNul=b'\x00' in body, containsEntity=b'<!ENTITY' in body.upper())
    result.update(xmlDeclarationOffset=body.find(b'<?xml'), plistTagOffset=body.find(b'<plist'),
        leadingXml=body.lstrip().startswith((b'<?xml', b'<plist')))
    if result['containsEntity']:
        return result
    try:
        value = plistlib.loads(body)
    except (ValueError, TypeError, OverflowError, RecursionError, plistlib.InvalidFileException,
            ExpatError) as error:
        result['parseError'] = next((label for label, cls in
            (('value', ValueError), ('type', TypeError), ('overflow', OverflowError),
             ('recursion', RecursionError), ('invalid-plist', plistlib.InvalidFileException))
            if type(error) is cls), 'other')
        return result
    result['parsed'] = True
    result['rootMap'] = type(value) is dict
    if type(value) is not dict:
        return result
    result.update(rootKeysCount=min(len(value), 33), rootKeysExact=set(value) == {'system-entities'})
    rows = value.get('system-entities')
    result['entitiesList'] = type(rows) is list
    if type(rows) is not list:
        return result
    result['rowCount'] = min(len(rows), 9)
    result['rowsBounded'] = 0 < len(rows) <= 8
    if not result['rowsBounded']:
        return result
    known = {'content-hint', 'dev-entry', 'potentially-mountable', 'mount-point', 'unmapped-content-hint'}
    kinds = (('string', str), ('boolean', bool), ('integer', int), ('array', list), ('map', dict), ('data', bytes))
    for row in rows:
        facts = {'map': type(row) is dict}
        if type(row) is dict:
            facts.update(keyCount=min(len(row), 33), keysBounded=len(row) <= 12,
                plainKeys=all(type(key) is str for key in row),
                unknownKeyCount=min(sum(key not in known for key in row), 33),
                volumeKindPresent='volume-kind' in row,
                volumeKindType='absent' if 'volume-kind' not in row else 'string' if type(row['volume-kind']) is str else 'other',
                volumeKindValue='absent' if 'volume-kind' not in row else row['volume-kind'] if type(row['volume-kind']) is str and row['volume-kind'] in ('hfs', 'apfs') else 'other',
                remainingUnknownKeyCount=min(sum(key not in known and key != 'volume-kind' for key in row), 33),
                knownValueKinds={key: next((label for label, cls in kinds if type(row[key]) is cls), 'other')
                    for key in sorted(known) if key in row},
                hasMount='mount-point' in row, mountMatches=type(row.get('mount-point')) is str and row['mount-point'] == str(mountpoint),
                deviceShape=type(row.get('dev-entry')) is str and re.fullmatch(r'/dev/disk[0-9]{1,5}(?:s[0-9]{1,3})?', row['dev-entry']) is not None,
                potentiallyMountableTrue=row.get('potentially-mountable') is True)
        result['rows'].append(facts)
    return result


def mount_observation(body, stderr, code, mountpoint):
    """Independent original mount observation for cleanup, NOT parser acceptance."""
    need(type(code) is int and code == 0 and type(body) is bytes and 0 < len(body) <= CAPTURE
         and type(stderr) is bytes and len(stderr) <= CAPTURE and b'\x00' not in body
         and b'<!ENTITY' not in body.upper())
    value = plistlib.loads(body)
    need(type(value) is dict and type(value.get('system-entities')) is list and 0 < len(value['system-entities']) <= 8)
    rows = value['system-entities']
    need(all(type(row) is dict and all(type(k) is str for k in row) and len(row) <= 12 for row in rows))
    mounted = [row for row in rows if 'mount-point' in row]
    need(len(mounted) == 1 and type(mounted[0]['mount-point']) is str and mounted[0]['mount-point'] == str(mountpoint))
    device = mounted[0].get('dev-entry')
    need(type(device) is str and re.fullmatch(r'/dev/disk[0-9]{1,5}(?:s[0-9]{1,3})?', device) is not None)
    allowed = {'content-hint', 'dev-entry', 'potentially-mountable', 'mount-point', 'unmapped-content-hint'}
    kinds = {'string': str, 'boolean': bool, 'integer': int, 'array': list, 'map': dict, 'data': bytes}
    facts = []
    for row in rows:
        facts.append({'keyCount': len(row), 'keys': sorted(k for k in row if k in allowed),
            'unknownKeys': any(k not in allowed for k in row),
            'valueKinds': {k: next((label for label, kind in kinds.items() if type(v) is kind), 'other')
                           for k, v in row.items() if k in allowed},
            'deviceShape': type(row.get('dev-entry')) is str and re.fullmatch(r'/dev/disk[0-9]{1,5}(?:s[0-9]{1,3})?', row['dev-entry']) is not None,
            'hasMount': 'mount-point' in row, 'mountMatches': row.get('mount-point') == str(mountpoint),
            'potentiallyMountableTrue': row.get('potentially-mountable') is True})
    return device, {'rows': facts, 'rowCount': len(rows), 'rootKeysExact': set(value) == {'system-entities'},
                    'mountedRows': 1, 'independentMountObservation': True}


def ledger_post_data(book, signature):
    """Finite failure diagnosis on existing originals, never custody authority."""
    result = {'bounded': type(book.entries) is list and len(book.entries) <= 96, 'checked': 0, 'allEqual': False}
    if not result['bounded']: return result
    for index, entry in enumerate(book.entries):
        if entry.get('fd') is None: continue
        facts = {'index': index, 'kind': entry.get('kind') if entry.get('kind') in
            ('source', 'directory', 'file', 'output', 'readonly-mount') else 'other'}
        expected = entry.get('identity')
        if type(expected) is not tuple or len(expected) not in (5, 9):
            result['firstMismatch'] = dict(facts, read='unbound'); return result
        try:
            held = signature(os.fstat(entry['fd']))[:len(expected)]
            parent = entry.get('parent')
            named = signature(os.stat(str(entry['path']) if parent is None else entry['path'].name,
                dir_fd=None if parent is None else parent['fd'], follow_symlinks=False))[:len(expected)]
        except (OSError, TypeError, ValueError, KeyError):
            result['firstMismatch'] = dict(facts, read='unavailable'); return result
        result['checked'] += 1
        if held != expected or named != expected:
            result['firstMismatch'] = dict(facts, read='known', held=[a == b for a,b in zip(held,expected)],
                named=[a == b for a,b in zip(named,expected)]); return result
    result['allEqual'] = True
    return result


def readonly_image(book, entry, signature):
    """One explicit pre-attach chmod on our same held newly-created image."""
    body = book.read(entry); before = entry['identity']
    os.fchmod(entry['fd'], 0o444); os.fsync(entry['fd'])
    after = signature(os.fstat(entry['fd']))
    named = signature(os.stat(entry['path'].name, dir_fd=entry['parent']['fd'], follow_symlinks=False))
    need(after == named and after[:2] == before[:2] and after[3:8] == before[3:8]
         and after[2] == stat.S_IFREG | 0o444 and os.pread(entry['fd'], len(body) + 1, 0) == body
         and not os.pread(entry['fd'], 1, len(body)))
    entry['identity'] = after
    need(book.read(entry) == body)



MOUNT_REASONS = ('package-original-mount-unavailable', 'package-mount-host-source-post',
    'package-readonly-mount-shape', 'package-readonly-mount-original', 'package-readonly-mount-post')


def mount_method(source):
    """Compile the authenticated genuine single method, not a copied validator."""
    tree = ast.parse(source)
    definitions = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))
                   and n.name in ('need', 'Refused', 'signature')]
    operations = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Operation']
    need(len(definitions) == 3 and len(operations) == 1)
    methods = [n for n in operations[0].body if isinstance(n, ast.FunctionDef) and n.name == 'mount_facts']
    need(len(methods) == 1)
    selected = ast.ClassDef(name='OriginalMountMethod', bases=[], keywords=[], body=methods, decorator_list=[])
    ast.copy_location(selected, operations[0])
    namespace = {'os': os, 'stat': stat}
    exec(compile(ast.fix_missing_locations(ast.Module(body=definitions + [selected], type_ignores=[])),
        str(ROOT / 'desktop/tools/macos_android_helper_package.py'), 'exec'), namespace)
    return namespace['OriginalMountMethod'], namespace['Refused']


def mount_projection(entry, work, device, fs):
    """Finite comparisons only; no raw paths, devices, dates or filesystem text."""
    held = os.fstat(entry['fd'])
    named = os.stat('package-mount', dir_fd=work['fd'], follow_symlinks=False)
    vflags = os.fstatvfs(entry['fd']).f_flag
    native = type(fs) is dict and type(fs.get('flags')) is int and 0 <= fs['flags'] < 1 << 32
    flags = fs['flags'] if native else None
    return {'diagnosticOnly': True, 'fullOperationIntegration': False,
        'vfsFlags': vflags if type(vflags) is int and 0 <= vflags < 1 << 32 else None,
        'fsFlags': flags, 'nativeFlagsUnsigned32': native,
        'vfsReadonly': type(vflags) is int and bool(vflags & os.ST_RDONLY),
        'nativeReadonly': native and bool(flags & 1), 'nativeLocal': native and bool(flags & 0x1000),
        'nativeUnion': native and bool(flags & 0x20), 'nativeMultilabel': native and bool(flags & 0x4000000),
        'nativeIgnoreOwnership': native and bool(flags & 0x200000),
        'nativeDontBrowse': native and bool(flags & 0x100000),
        'typeName': fs.get('typeName') if type(fs) is dict and fs.get('typeName') in ('hfs', 'apfs') else 'other',
        'mountOnMatches': type(fs) is dict and fs.get('mountOn') == str(work['path'] / 'package-mount'),
        'mountFromMatches': type(fs) is dict and fs.get('mountFrom') == device,
        'heldNamedFullSignature': (held.st_dev, held.st_ino, held.st_mode, held.st_nlink, held.st_uid,
            held.st_gid, held.st_size, held.st_mtime_ns, held.st_ctime_ns) ==
            (named.st_dev, named.st_ino, named.st_mode, named.st_nlink, named.st_uid,
            named.st_gid, named.st_size, named.st_mtime_ns, named.st_ctime_ns),
        'registeredIdentityMatches': (held.st_dev, held.st_ino, held.st_mode, held.st_uid, held.st_gid) == entry['identity'],
        'directory': stat.S_ISDIR(held.st_mode), 'ownerAllowed': held.st_uid in (0, os.getuid()),
        'notGroupOtherWritable': not bool(held.st_mode & 0o022),
        'deviceDiffersFromWork': held.st_dev != work['identity'][0]}


def original_mount_diagnostic(helper, provider, book, root, mount, device, host_source, end, target):
    """Actual Darwin fstatfs and genuine method; lifecycle ports explicitly bounded."""
    class SameClock:
        def check(self):
            need(time.monotonic_ns() < end)
    clock = SameClock()
    clock.check()
    api = provider.DarwinAPI(clock, target=target)
    clock.check()
    method, refused = mount_method(helper)
    original = method()
    entry = {'fd': mount['fd'], 'closed': mount['closed'], 'parent': root['fd'], 'name': 'package-mount',
        'identity': mount['identity']}
    source, body = host_source
    last = {'fs': None}
    class OneOriginalFilesystem:
        def filesystem(self, fd):
            need(last['fs'] is None and fd == mount['fd'])
            last['fs'] = api.filesystem(fd)
            return last['fs']
    def work_post(work):
        need(work is original.work_entry)
        book.check_one(root)
    original.package_clock = clock.check
    original.recheck_directory = work_post
    original.work_entry = {'fd': root['fd'], 'identity': root['identity']}
    original.work = root['path']
    original.entry_registry = {id(entry): entry}
    original.mount_api = OneOriginalFilesystem()
    original.mount_host_source = (source, body)
    original.read = book.read
    original.mount_device = device
    result = {'attempted': True, 'methodPassed': False, 'reason': None, 'errorType': None,
        'genuineSingleMethod': True, 'sameDeadline': True, 'fullOperationIntegration': False}
    try:
        fs = original.mount_facts(entry)
        need(fs is last['fs'])
        result['methodPassed'] = True
    except BaseException as error:
        result['errorType'] = 'helper-refused' if type(error) is refused else 'os-error' if type(error) is OSError else 'other'
        args = BaseException.args.__get__(error)
        result['reason'] = args[0] if type(error) is refused and type(args) is tuple and len(args) == 1 and type(args[0]) is str and args[0] in MOUNT_REASONS else 'unclassified'
    result['facts'] = mount_projection(entry, dict(root, identity=root['identity']), device, last['fs'])
    clock.check()
    need(book.read(source) == body)
    book.check_one(root); book.check_one(mount)
    return result


def main():
    os.umask(0o077)
    end = time.monotonic_ns() + 180_000_000_000
    report = context(dict(os.environ))
    report.update(diagnosisComplete=False, parserPassed=False, parserReason=None, originalDetached=False)
    resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))
    book = None; scratch = None; mount = None; device = None; calls = []; closed = False; retired = False
    attach_observed = False; detached = False; source_post = False
    report['probeStage'] = 'bootstrap'
    donor_refused = None
    failure = None; stager = None; owner = None; mount_entries = []; root = None; private_files = []; source_entries = []; directories = []
    try:
        fd = os.open(ROOT / 'desktop/tools/macos_e2_native_fixture.py', READ)
        try:
            info = os.fstat(fd); source = os.pread(fd, SOURCE_PINS['desktop/tools/macos_e2_native_fixture.py'][0] + 1, 0)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                 and len(source) == info.st_size == SOURCE_PINS['desktop/tools/macos_e2_native_fixture.py'][0] and not os.pread(fd, 1, info.st_size)
                 and digest(source) == SOURCE_PINS['desktop/tools/macos_e2_native_fixture.py'][1])
            Book, signature, donor_refused = original_class(source); book = Book()
            parent = book.directory((ROOT / 'desktop/tools').absolute())
            entry = book.register(fd, ROOT / 'desktop/tools/macos_e2_native_fixture.py', 'source')
            fd = None; entry['parent'] = parent; entry['identity'] = signature(info)
            book.check_one(entry)
        finally:
            if fd is not None: os.close(fd)
        need(len(SOURCE_PINS) <= 16)
        sources = {}
        for relative, (size, expected) in SOURCE_PINS.items():
            item, body = book.file(ROOT / relative, size, modes=(0o644, 0o444))
            need(len(body) == size and digest(body) == expected); sources[relative] = body; source_entries.append((item, digest(body)))
        own, ownbody = book.file(Path(__file__).absolute(), 65536, modes=(0o644,))
        need(digest(ownbody) == report['observerSourceSha256']); source_entries.append((own, digest(ownbody)))
        _, head = book.file(ROOT / '.git/HEAD', 41, modes=(0o644,)); need(head == report['source'].encode() + b'\n')
        _, system = book.file(Path('/System/Library/CoreServices/SystemVersion.plist'), 8192, uid=0)
        product = plistlib.loads(system).get('ProductVersion')
        need(type(product) is str and re.fullmatch(r'26(?:\.[0-9]{1,2}){1,2}', product) is not None)
        tool, toolbody = book.file(Path('/usr/bin/hdiutil'), LIMIT, uid=0, modes=(0o755, 0o555))
        report['toolSha256'] = digest(toolbody); source_entries.append((tool, digest(toolbody))); del toolbody
        stager = module(sources['desktop/tools/stage_macos_installed.py'], '_mrk_hfs_stager', ROOT / 'desktop/tools/stage_macos_installed.py')
        aqua = module(sources['desktop/tools/macos_aqua_qualification.py'], '_mrk_hfs_aqua', ROOT / 'desktop/tools/macos_aqua_qualification.py')
        book.check(); owner = aqua.load_owner(ROOT); book.check()
        original_failure = failure_projection(sources['desktop/tools/macos_android_helper_package.py'])
        parent = book.directory(PARENT)
        need(os.fstat(parent['fd']).st_uid == os.getuid() and os.fstat(parent['fd']).st_gid == os.getgid())
        name = 'mrk-hfs-parser-' + os.urandom(16).hex(); os.mkdir(name, 0o700, dir_fd=parent['fd'])
        scratch = PARENT / name
        root = book.directory(scratch); root_origin = root['identity']; need(stat.S_IMODE(os.fstat(root['fd']).st_mode) == 0o700 and os.fstat(root['fd']).st_uid == os.getuid() and os.fstat(root['fd']).st_gid == os.getgid() and not os.listdir(root['fd']))
        need(os.fstatvfs(root['fd']).f_bavail * os.fstatvfs(root['fd']).f_frsize >= 128 * 1024 * 1024)
        for leaf in ('home', 'tmp', 'carrier', 'package-mount'):
            os.mkdir(leaf, 0o700, dir_fd=root['fd']); directories.append(book.directory(scratch / leaf))
        for leaf, body in NAMES.items():
            book.publish(scratch / 'carrier' / leaf, body, mode=0o444)
            item, original = book.file(scratch / 'carrier' / leaf, 1024, modes=(0o444,)); need(original == body); private_files.append(item)
        carrier = book.directory(scratch / 'carrier'); need(set(os.listdir(carrier['fd'])) == set(NAMES))
        environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(scratch / 'home'), 'TMPDIR': str(scratch / 'tmp'),
                       'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}
        def call(role, argv, maximum):
            need(time.monotonic_ns() + (maximum + 5) * 1_000_000_000 < end and len(book.entries) < 96)
            book.check(); need(all(digest(book.read(item)) == expected for item, expected in source_entries))
            row = {'role': role, 'entered': True, 'returned': False, 'returncode': None}; calls.append(row)
            try:
                result = owner.run_owned(argv, environ=environment, cwd=scratch, timeout=maximum, capture=True, text=False, output_limit=CAPTURE)
            except BaseException as error:
                # Optional finite diagnostic never replaces this same original.
                try:
                    row['originalFailure'] = original_failure(error, owner, ROOT, maximum, CAPTURE)
                    builtins = {'TypeError': TypeError, 'ValueError': ValueError, 'OSError': OSError,
                        'ImportError': ImportError, 'AttributeError': AttributeError, 'RuntimeError': RuntimeError,
                        'KeyboardInterrupt': KeyboardInterrupt, 'SystemExit': SystemExit}
                    row['builtinErrorType'] = next((name for name, cls in builtins.items() if type(error) is cls), 'other')
                    if any(type(error) is vars(owner).get(name) for name in ('ProcessError', 'ProcessCleanupError', 'ProcessOutcomeUnknown', 'ProcessInterrupted')):
                        fields = BaseException.__dict__['__dict__'].__get__(error)
                        row['ownerFailure'] = {name: fields.get(name) if type(fields.get(name)) is bool else None
                            for name in ('dispatched', 'contained', 'cleanup_complete')}
                except BaseException:
                    pass
                raise
            need(type(result) is subprocess.CompletedProcess and result.args == argv and type(result.returncode) is int
                 and type(result.stdout) is bytes and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= CAPTURE)
            row.update(returned=True, returncode=result.returncode, stdoutSha256=digest(result.stdout), stderrSha256=digest(result.stderr))
            row['postStage'] = 'book-post'; book.check()
            row['postStage'] = 'source-post'; need(all(digest(book.read(item)) == expected for item, expected in source_entries))
            row['postStage'] = 'deadline-post'; need(time.monotonic_ns() < end)
            row['postStage'] = 'complete'; return result
        image = scratch / 'synthetic.dmg'
        result = call('create', ['/usr/bin/hdiutil', 'create', '-srcfolder', str(scratch / 'carrier'), '-fs', 'HFS+', '-format', 'UDZO',
            '-volname', 'MRK Synthetic Parser Probe', str(image)], 60)
        need(result.returncode == 0)
        image_entry, imagebody = book.file(image, LIMIT, modes=(0o644, 0o600)); private_files.append(image_entry); image_digest = digest(imagebody); report['imageBytes'] = len(imagebody); del imagebody
        readonly_image(book, image_entry, signature)
        mountpoint = scratch / 'package-mount'
        placeholder = book.directories[mountpoint]
        need(not os.listdir(placeholder['fd'])); book.check_one(placeholder); book.close(placeholder); need(placeholder['closed'])
        result = call('attach', ['/usr/bin/hdiutil', 'attach', str(image), '-readonly', '-nobrowse', '-noautoopen', '-mountpoint', str(mountpoint), '-plist'], 30)
        report['probeStage'] = 'attach-shape'
        report['attachDiagnostic'] = attach_shape_data(result.stdout, result.stderr, result.returncode, mountpoint)
        report['probeStage'] = 'observation'
        device, report['attachShape'] = mount_observation(result.stdout, result.stderr, result.returncode, mountpoint)
        attach_observed = True
        fd = os.open('package-mount', READ | os.O_DIRECTORY, dir_fd=root['fd'])
        mount = book.register(fd, mountpoint, 'readonly-mount'); mount['parent'] = root
        info = os.fstat(fd); mount['identity'] = signature(info)[:5]
        need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid()) and not stat.S_IMODE(info.st_mode) & 0o022
             and os.fstatvfs(fd).f_flag & os.ST_RDONLY); book.check_one(mount)
        book.directories[mountpoint] = mount
        report['mountFacts'] = {'readonly': bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY),
            'heldNamedIdentity': signature(os.fstat(fd))[:5] == signature(os.stat('package-mount', dir_fd=root['fd'], follow_symlinks=False))[:5],
            'threeFileRoster': set(os.listdir(fd)) == set(NAMES), 'modes0444': True, 'nlink1': True, 'bytesEqual': True}
        actual = {}
        need(set(os.listdir(fd)) == set(NAMES))
        for leaf, expected in NAMES.items():
            item_info = os.stat(leaf, dir_fd=fd, follow_symlinks=False); need(item_info.st_uid in (0, os.getuid()))
            item, body = book.file(mountpoint / leaf, 1024, uid=item_info.st_uid, modes=None)
            mount_entries.append(item); actual[leaf] = (body, stat.S_IMODE(os.fstat(item['fd']).st_mode))
            report['mountFacts']['modes0444'] &= stat.S_IMODE(os.fstat(item['fd']).st_mode) == 0o444
            report['mountFacts']['nlink1'] &= os.fstat(item['fd']).st_nlink == 1
            report['mountFacts']['bytesEqual'] &= body == expected
        host_relative = 'desktop/tools/macos_xcode_host_preparation.py'
        host_entry = next(item for item, _ in source_entries if item['path'] == ROOT / host_relative)
        provider = module(sources[host_relative], '_mrk_hfs_mount_provider', ROOT / host_relative)
        report['probeStage'] = 'original-mount-facts'
        report['originalMountDiagnostic'] = original_mount_diagnostic(
            sources['desktop/tools/macos_android_helper_package.py'], provider, book, root, mount,
            device, (host_entry, sources[host_relative]), end, report['target'])
        report['parserPassed'] = False
        try:
            parsed = stager.distribution_mount_data(result.stdout, result.stderr, result.returncode, mountpoint)
            need(parsed == device)
            stager.distribution_layout_data(os.listdir(fd), 'Install.pkg', NAMES, actual)
            report['parserPassed'] = True; report['parserReason'] = None
        except BaseException as error:
            report['parserReason'] = parser_reason(error, stager)
        book.check(); need(digest(book.read(image_entry)) == image_digest)
        for item in reversed(mount_entries): book.close(item)
        book.close(mount); need(all(item['closed'] for item in mount_entries + [mount]))
        result = call('detach', ['/usr/bin/hdiutil', 'detach', device], 30); need(result.returncode == 0)
        device = None; detached = True; report['originalDetached'] = True
        book.directories.pop(mountpoint); mount = None
        book.check(); need(time.monotonic_ns() < end)
        report['diagnosisComplete'] = True
    except BaseException as error:
        failure = 'probe-refused'
        if donor_refused is not None and type(error) is donor_refused:
            arguments = BaseException.args.__get__(error)
            allowed = ('original-changed', 'original-unbound', 'original-short-read', 'original-grew')
            report['donorReason'] = arguments[0] if type(arguments) is tuple and len(arguments) == 1 and type(arguments[0]) is str and arguments[0] in allowed else 'other'
        if book is not None:
            try: report['ledgerPost'] = ledger_post_data(book, signature)
            except BaseException: report['ledgerPost'] = {'read': 'unavailable'}
    finally:
        if device is not None and book is not None and owner is not None and calls and all(r['returned'] for r in calls):
            try:
                for item in reversed(mount_entries): book.check_one(item); book.close(item)
                if mount is not None: book.check_one(mount); book.close(mount)
                need(all(item['closed'] for item in mount_entries) and (mount is None or mount['closed']))
                result = call('detach', ['/usr/bin/hdiutil', 'detach', device], 30); need(result.returncode == 0)
                device = None; detached = True; report['originalDetached'] = True
            except BaseException:
                failure = 'cleanup-unconfirmed'
        if (book is not None and scratch is not None and root is not None and device is None
                and all(r['returned'] for r in calls)
                and (not any(r['role'] == 'attach' for r in calls) or attach_observed and detached)):
            try:
                book.check(); need(root['identity'] == root_origin)
                need(set(os.listdir(root['fd'])) == {'home', 'tmp', 'carrier', 'package-mount', 'synthetic.dmg'})
                for leaf in ('home', 'tmp', 'package-mount'):
                    info = os.stat(leaf, dir_fd=root['fd'], follow_symlinks=False)
                    known = next(item for item in directories if item['path'].name == leaf)
                    need(signature(info)[:5] == known['identity'])
                    fd = os.open(leaf, READ | os.O_DIRECTORY, dir_fd=root['fd'])
                    empty = book.register(fd, scratch / leaf, 'retirement-directory'); empty['parent'] = root
                    empty['identity'] = signature(os.fstat(fd))[:5]
                    book.check_one(empty); need(not os.listdir(fd)); book.close(empty); need(empty['closed'])
                    book.close(known); need(known['closed'])
                    need(signature(os.stat(leaf, dir_fd=root['fd'], follow_symlinks=False))[:5] == known['identity'])
                    os.rmdir(leaf, dir_fd=root['fd'])
                carrier = book.directories[scratch / 'carrier']; book.check_one(carrier)
                need(set(os.listdir(carrier['fd'])) == set(NAMES))
                for item in private_files:
                    book.check_one(item); book.close(item); need(item['closed'])
                    parent_entry = item['parent']
                    need(signature(os.stat(item['path'].name, dir_fd=parent_entry['fd'], follow_symlinks=False)) == item['identity'])
                    os.unlink(item['path'].name, dir_fd=parent_entry['fd'])
                need(not os.listdir(carrier['fd'])); book.close(carrier); need(carrier['closed'])
                os.rmdir('carrier', dir_fd=root['fd']); need(not os.listdir(root['fd']))
                book.check_one(root); book.close(root); need(root['closed'])
                need(signature(os.stat(scratch.name, dir_fd=parent['fd'], follow_symlinks=False))[:5] == root_origin)
                os.rmdir(scratch.name, dir_fd=parent['fd'])
                try: os.stat(scratch.name, dir_fd=parent['fd'], follow_symlinks=False)
                except FileNotFoundError: retired = True
                need(retired); book.check()
            except BaseException: failure = 'retirement-unconfirmed'
        if book is not None:
            try:
                for item, expected in source_entries:
                    ancestor = item.get('parent')
                    while ancestor is not None:
                        book.check_one(ancestor); ancestor = ancestor.get('parent')
                    need(digest(book.read(item)) == expected)
                source_post = len(source_entries) == len(SOURCE_PINS) + 2
            except BaseException: failure = 'original-post-unconfirmed'
            closed = book.finish()
        cleanup_complete = closed and retired and device is None and attach_observed and detached and all(r['returned'] for r in calls)
        if not cleanup_complete and failure is None:
            failure = 'cleanup-unconfirmed'
    need(source_post)
    if time.monotonic_ns() >= end:
        failure = 'probe-deadline'
    report.update(schemaVersion=1, kind='mrk-synthetic-hfs-parser-diagnostic-v1', calls=calls,
        originalClosesKnown=closed, exactTaskRetired=retired, sourcePostKnown=source_post, cleanupComplete=cleanup_complete,
        attachmentObserved=attach_observed, detachKnown=detached, failure=failure, productReady=False, installerEntered=False,
        runtimeExecuted=False, credentialsRead=False, diagnosisOnly=True)
    body = (json.dumps(report, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    need(len(body) <= 8192)
    output = Book()
    try:
        output.publish(ROOT / PUBLIC, body); output.check()
    finally:
        need(output.finish())
    # An incomplete diagnostic may be preserved, never counted successful.
    return 0 if failure is None and cleanup_complete and report['diagnosisComplete'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Refused as error:
        arguments = BaseException.args.__get__(error)
        token = (arguments[0] if type(arguments) is tuple and len(arguments) == 1
                 and type(arguments[0]) is str and arguments[0] in INTERPRETER_REFUSALS else 'probe-refused')
        print('hfs-parser-admission:' + token, file=sys.stderr)
        raise SystemExit(1) from None
