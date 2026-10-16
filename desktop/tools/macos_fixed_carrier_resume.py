"""One fixed ce644 ARM carrier -> fresh Installer/readback owner. No compiler, signing, re-notary, history/P0 enrollment or generic cache.

Transport/codec/custody portions are authenticated copies of accepted P0 originals;
this is a separate FIRST two-source diagnostic profile, never P0 qualification.
"""
import ctypes
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import sys
import time

# One entry deadline includes the remaining imports. Acquisition still consumes
# its parent's separate original endpoint; it never gets a renewed budget.
if __name__ == '__main__':
    os.environ['MRK_FIXED_RESUME_STARTED_NS'] = str(time.monotonic_ns())
import urllib.error
import urllib.parse
import urllib.request
import ssl
import zipfile
import zlib
import argparse

REPOSITORY = 'Apdelrahman1911/mobile-release-kit'
WORKFLOW = '.github/workflows/desktop-macos-installed.yml'
WORKFLOW_ID = 363563168
RESUME_WORKFLOW = '.github/workflows/desktop-macos-fixed-carrier-resume.yml'
ENROLLMENT_REF = 'refs/heads/verify/desktop-macos-installed'
TARGETS = ('aarch64-apple-darwin',)
LIMIT = 512 << 20
SOURCE_LIMIT = 164 << 10
MAX_ORIGINALS = 96
OUTPUT_LIMIT = 2 << 20
TERMINAL_LIMIT = 64 << 10
TRANSPORT_LIMIT = LIMIT
MEMBERS = {'MobileReleaseKit.dmg': LIMIT, 'PREVIEW.json': 16384, 'public-verification-evidence.json': 128 << 10}
STATE = {'phase': 'admission', 'firstFailurePhase': None, 'lastRole': None, 'originalClosesKnown': False,
         'privateOutputsRetired': False, 'workloadsKnownSettled': False, 'resourceAdmission': None, 'installerObservation': None}
SCOPE = 'fixed-ce644-arm-carrier-ios-unsigned-only'
ORIGIN = {'source': 'ce644711fb6e2bea26182473441aac192d5638e1', 'tree': 'e5c4c43b2a903b3040d24c8bfa94b5236fd12882',
 'runId': '38649386495', 'runAttempt': '1', 'jobId': '116144135875', 'artifactId': '11935748046',
 'artifactBytes': 73668046, 'artifactSha256': '2c377f7243406310deb09e5957e2ce5981765b996b25403de842efd077ee6c3d',
 'qualificationEvidenceSha256': 'ffa120afe531784a4518b6b354f43b079a52fa4e7fb85618f0a203c43d0e1d67',
 'qualificationArtifact': {'artifactId': '11934984449', 'artifactBytes': 64585,
  'artifactSha256': '919206c30a2a6116058728b0000f418449016c0d5e6facd937266a57fc6adf06'},
 'package': {'name': 'Install.pkg', 'bytes': 72045160, 'sha256': '62f43d44d9f46009fe4c82056ea6fc3c64b34fee436b517d0e80c16c194a92d2'},
 'descriptor': {'name': 'producer.json', 'bytes': 1330, 'sha256': '19cab75ed19ee885bcd0b99c860cb3ee74d4bc917402e96b1a1e21066291dc24'},
 'signature': {'name': 'producer.sig', 'bytes': 256, 'sha256': '28ed5658f1d0aa49d9213cb818984379b8a2df4a11e970b8987dda80f8dc2a7e'},
 'imageBytes': 73665231, 'imageSha256': '66945f93f8331ae5f4ad945dbb248b263c77b091de6874b84366ddf142685e45',
 'packageVersion': '0.1.1', 'release': 'macos26-arm64-desktop-01'}
# CI code comes from this run's trusted actions/checkout, not embedded source snapshots.
# Keep artifact, TLS and signing-certificate integrity separate from code selection.
SOURCE_MODULE_LIMIT = 1 << 20
SOURCE_FILES = (
    'desktop/tools/macos_e2_native_fixture.py',
    'desktop/tools/stage_macos_installed.py',
    'desktop/tools/macos_public_verification_evidence.py',
    'desktop/tools/macos_aqua_qualification.py',
    'desktop/tools/macos_xcode_host_preparation.py',
    'src/mobile_release/owned_process.py',
    'src/mobile_release/_command_process.py',
    'src/mobile_release/_native_process.py',
    'src/mobile_release/cancellation.py',
    'src/mobile_release/__init__.py',
    'src/mobile_release/errors.py',
    'src/mobile_release/_lifetime_evidence.py',
    'src/mobile_release/_store_lane_contract.py',
    'src/mobile_release/_store_lane_evidence.py',
)
SIGNING_CERTIFICATE = ('desktop/packaging/macos-install-producer-certificates/leaf.der', 1490, 'e5ba1d05f136fbef3ca5816f0efb1e946cb2cfb81819b745d9f914e7e9256d72')

TLS_CA_PATH = 'desktop/macos-installed-inputs/fixed-consumer-tls/cacert.pem'
TLS_CA_BYTES = 240216
TLS_CA_SHA256 = '9cc2a774b5198dcff14d9be1e66091f538975d867ce029a96bce15a55dfd730f'

HOST_FILES = ('pyvenv.cfg', 'bin/python', 'bin/python3', 'bin/python3.14',
              'bin/activate', 'bin/activate.csh', 'bin/activate.fish', 'bin/Activate.ps1')
HOST_OPTIONAL = 'bin/𝜋thon'  # Documented CPython3.14 UTF-8 executable alias.
HOST_DIRS = ('.', 'bin', 'include', 'lib', 'lib/python3.14', 'lib/python3.14/site-packages')
HOST_BYTES = (256 << 20) + (256 << 10)


def host_read(path, limit, *, base=False):
    """Small preparation originals; shared base is observed, never modified."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    primary = None
    try:
        before = identity(os.fstat(fd))
        need(stat.S_ISREG(before[2]) and before[3] in (0, os.getuid()) and before[5] == 1
             and 0 < before[6] <= limit and (base or not before[2] & 0o022), 'resume-host-file')
        body = os.pread(fd, before[6] + 1, 0)
        need(len(body) == before[6] and not os.pread(fd, 1, before[6])
             and identity(os.fstat(fd)) == before == identity(os.stat(path, follow_symlinks=False)), 'resume-host-file-post')
        return before, body
    except BaseException as error:
        primary = error
        raise
    finally:
        consumed, fd = fd, None
        try: os.close(consumed)
        except BaseException:
            if primary is None: raise ValueError('resume-host-file-close') from None
            BaseException.add_note(primary, 'resume-host-file-close')


def host_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    primary = None
    try:
        before = identity(os.fstat(fd))[:5]
        need(stat.S_ISDIR(before[2]) and stat.S_IMODE(before[2]) == 0o700
             and before[3:5] == (os.getuid(), os.getgid()), 'resume-host-directory')
        names = os.listdir(fd)
        need(len(names) <= 10 and all(type(n) is str and '/' not in n for n in names)
             and identity(os.fstat(fd))[:5] == before == identity(os.stat(path, follow_symlinks=False))[:5], 'resume-host-directory-post')
        return before, names
    except BaseException as error:
        primary = error
        raise
    finally:
        consumed, fd = fd, None
        try: os.close(consumed)
        except BaseException:
            if primary is None: raise ValueError('resume-host-directory-close') from None
            BaseException.add_note(primary, 'resume-host-directory-close')


def host_config_data(body, base, root):
    need(type(body) is bytes and 0 < len(body) <= 4096, 'resume-host-config-size')
    cfg = {}
    for line in body.decode('utf-8').splitlines():
        key, sep, value = line.partition('='); key, value = key.strip(), value.strip()
        need(sep and key not in cfg, 'resume-host-config-key')
        cfg[key] = value
    need(set(cfg) == {'home', 'include-system-site-packages', 'version', 'executable', 'command'}
         and cfg['home'] == str(Path(base['copyPath']).parent)
         and cfg['include-system-site-packages'] == 'false' and cfg['version'] == '3.14.7'
         and cfg['executable'] == base['executable']
         and cfg['command'] == base['launcherPath'] + ' -m venv --copies --without-pip --without-scm-ignore-files ' + str(root), 'resume-host-config-binding')
    return cfg


def host_snapshot(root, directory, read_file, *, sidecar=False):
    """Only the documented without-pip Darwin venv roster, no glob discovery."""
    dirs, files, bodies, names = [], [], {}, {}
    for relative in HOST_DIRS:
        original, children = directory(root if relative == '.' else root / relative)
        need(stat.S_ISDIR(original[2]) and stat.S_IMODE(original[2]) == 0o700
             and original[3:5] == (os.getuid(), os.getgid()), 'resume-host-roster-directory')
        dirs.append({'path': relative, 'identity': list(original[:5])})
        names[relative] = set(children)
        need(len(children) == len(names[relative]), 'resume-host-roster-duplicates')
    optional = HOST_OPTIONAL.split('/')[-1] in names['bin']
    selected = HOST_FILES + ((HOST_OPTIONAL,) if optional else ())
    expected = {'.': {'bin', 'include', 'lib', 'pyvenv.cfg'} | ({'host-binding.json'} if sidecar else set()),
                'bin': {Path(p).name for p in selected if p.startswith('bin/')},
                'include': set(), 'lib': {'python3.14'}, 'lib/python3.14': {'site-packages'},
                'lib/python3.14/site-packages': set()}
    need(names == expected, 'resume-host-roster')
    total = 0
    for relative in selected:
        executable = relative in ('bin/python', 'bin/python3', 'bin/python3.14', HOST_OPTIONAL)
        limit = (64 << 20) if executable else (4096 if relative == 'pyvenv.cfg' else 64 << 10)
        original, body = read_file(root / relative, limit)
        need(stat.S_ISREG(original[2]) and original[3:6] == (os.getuid(), os.getgid(), 1)
             and not original[2] & 0o022 and 0 < original[6] == len(body) <= limit
             and (not executable or stat.S_IMODE(original[2]) == 0o755), 'resume-host-roster-file')
        total += len(body); need(total <= HOST_BYTES, 'resume-host-roster-bytes')
        files.append({'path': relative, 'identity': list(original), 'sha256': sha(body)})
        if relative == 'pyvenv.cfg': bodies[relative] = body
    return {'directories': dirs, 'files': files, 'totalBytes': total}, bodies['pyvenv.cfg']


def host_selection_data(binding, snapshot, cfg_body, root, context, source, run, attempt):
    keys = {'schemaVersion', 'source', 'runId', 'runAttempt', 'base', 'prefix', 'basePrefix', 'baseExecutable',
            'directories', 'files', 'totalBytes', 'retainedUntilHostedTeardown'}
    need(type(binding) is dict and set(binding) == keys and type(binding['schemaVersion']) is int
         and binding['schemaVersion'] == 1 and binding['source'] == source and binding['runId'] == run
         and binding['runAttempt'] == attempt and binding['retainedUntilHostedTeardown'] is True, 'resume-host-binding')
    base = binding['base']
    need(type(base) is dict and set(base) == {'launcherPath', 'executable', 'copyPath', 'copyExecutable', 'prefix', 'identity', 'sha256'}
         and all(type(base[k]) is str and 0 < len(base[k]) <= 4096 and os.path.isabs(base[k])
                 and os.path.normpath(base[k]) == base[k] for k in ('launcherPath', 'executable', 'copyPath', 'copyExecutable', 'prefix'))
         and type(base['identity']) is list and len(base['identity']) == 9 and all(type(n) is int for n in base['identity'])
         and type(base['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', base['sha256']), 'resume-host-base-shape')
    need(context == {'executable': str(root / 'bin/python3'), 'prefix': str(root), 'basePrefix': base['prefix'],
                     'baseExecutable': base['copyExecutable']}
         and binding['prefix'] == context['prefix'] and binding['basePrefix'] == context['basePrefix']
         and binding['baseExecutable'] == context['baseExecutable'] and binding['basePrefix'] != binding['prefix'], 'resume-host-selection')
    need(all(binding[k] == snapshot[k] for k in ('directories', 'files', 'totalBytes'))
         and type(binding['totalBytes']) is int and 0 < binding['totalBytes'] <= HOST_BYTES, 'resume-host-snapshot-binding')
    host_config_data(cfg_body, base, root)
    copied = [row for row in snapshot['files'] if row['path'] in ('bin/python', 'bin/python3', 'bin/python3.14', HOST_OPTIONAL)]
    need(all(row['sha256'] == base['sha256'] and row['identity'][6] == base['identity'][6] for row in copied), 'resume-host-copy-binding')
    return binding['totalBytes']


class Refused(ValueError):
    """Only finite tokens; no native/HTTP error text is public."""


def need(value, reason):
    if not value:
        raise Refused(reason)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'p0-json-duplicate')
        result[key] = value
    return result


def constant(_):
    raise Refused('p0-json-number')


def decode(body, *, allow_finite_floats=False):
    need(type(allow_finite_floats) is bool, 'p0-json-float-policy')
    need(type(body) is bytes and len(body) <= 256 << 10, 'p0-json-size')
    value = json.loads(body, object_pairs_hook=pairs, parse_constant=constant)
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop(); count += 1
        need(depth <= 20 and count <= 32768, 'p0-json-graph')
        if type(item) is dict:
            need(len(item) <= 256 and all(type(k) is str and len(k) <= 256 for k in item), 'p0-json-width')
            pending.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            need(len(item) <= 2048, 'p0-json-width')
            pending.extend((v, depth + 1) for v in item)
        elif type(item) is str:
            need(len(item) <= 16384, 'p0-json-string')
        else:
            need(item is None or type(item) in (bool, int)
                 or allow_finite_floats and type(item) is float and -sys.float_info.max <= item <= sys.float_info.max,
                 'p0-json-scalar')
    return value


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


class Deadline:
    def __init__(self, now=time.monotonic_ns, *, started=None):
        self.now = now
        observed = now()
        need(started is None or type(started) is int and 0 < started <= observed, 'p0-original-start')
        self.started = observed if started is None else started
        self.deadline = self.started + 600_000_000_000
        self.work = self.deadline - 60_000_000_000
        self.finality = False

    def check(self):
        value = self.now()
        need(self.started <= value < (self.deadline if self.finality else self.work), 'p0-task-deadline')
        return value

    def seconds(self, maximum):
        left = ((self.deadline if self.finality else self.work) - self.check()) // 1_000_000_000
        # Leave the original owner's finality work inside the original endpoint.
        result = min(maximum, left - (15 if self.finality else 30))
        need(result > 0, 'p0-command-admission-deadline')
        return int(result)


class OriginalQuota:
    """Reserve the whole missing directory+leaf quote BEFORE donor os.open.

    No fallible check is inserted in donor register. Reservations never refund
    failed calls or consumed closes. Donor Originals/close semantics are intact.
    """
    def __init__(self):
        self.reserved = 0
        self.books = []

    def reserve(self, count):
        need(type(count) is int and 0 <= count <= MAX_ORIGINALS
             and self.reserved + count <= MAX_ORIGINALS, 'p0-original-admission')
        self.reserved += count

    def book(self, factory):
        book = factory()
        self.books.append(book)
        return book

    def call(self, book, method, path, *args, **kwargs):
        need(method in ('directory', 'file', 'publish') and book in self.books, 'p0-original-method')
        path = Path(path)
        need(path.is_absolute() and str(path) == os.path.normpath(path) and len(path.parts) <= 40, 'p0-original-path')
        parent = path if method == 'directory' else path.parent
        count = int(method != 'directory')
        while parent not in book.directories:
            count += 1
            if parent == Path('/'):
                break
            parent = parent.parent
        self.reserve(count)
        before = len(book.entries)
        result = getattr(book, method)(path, *args, **kwargs)
        need(len(book.entries) - before == count, 'p0-original-quote-correspondence')
        return result

    def check(self):
        for book in self.books:
            for path, entry in getattr(book, '_p0_borrowed', ()):
                need(book.directories.get(path) is entry and entry['fd'] is not None and not entry['closed']
                     and not any(owned is entry for owned in book.entries), 'p0-borrowed-parent-custody')
            book.check()

    def finish(self):
        settled = True
        for book in reversed(self.books):
            settled = book.finish() and settled
        return settled


class _FixedSudoEntry:
    """A live view, never an independent descriptor owner."""
    def __init__(self, node):
        self.node = node

    def __getitem__(self, key):
        if key == 'fd': return self.node.fd
        if key == 'kind': return self.node.kind
        raise KeyError(key)


class FixedSudoOriginals:
    """Reuse the host's exact protected-sudo policy, not a read fallback."""
    def __init__(self, module, api, clock, uid):
        # Construction is inert; global registration precedes every acquisition.
        self.module, self.clock = module, clock
        self.book = module.Originals(api, {'uid': uid}, clock)
        self.entries = []
        self.attempted = self.ready = self.failed = self.finished = False
        self.close_uncertain = False

    @property
    def errors(self):
        return self.book.errors

    def acquire(self, quota):
        need(self in quota.books and not self.attempted and not self.finished, 'resume-sudo-registration')
        self.attempted = True
        quota.reserve(4)  # Independent root/usr/bin/sudo originals; never refund.
        parent = None
        for name, kind, policy, role in (
                ('/', 'directory', 'native', 'os-provisioner-root'),
                ('usr', 'directory', 'native', 'os-provisioner-usr'),
                ('bin', 'directory', 'native', 'os-provisioner-bin'),
                ('sudo', 'file', 'sudo', 'os-provisioner-sudo')):
            node = self.book.open(parent, name, kind, policy, role)
            self.entries.append(_FixedSudoEntry(node))
            need(not self.errors and node.fd is not None and node.close_state == 'owned'
                 and node.pre and node.expected is node.pre, 'resume-sudo-original')
            parent = node
        need(len(self.book.nodes) == len(self.entries) == 4, 'resume-sudo-original-count')
        self.ready = True
        self.check()

    def check_one(self, entry):
        try:
            self.clock.check()
            need(self.ready and not self.failed and not self.finished and not self.errors
                 and any(held is entry for held in self.entries), 'resume-sudo-live-entry')
            node = entry.node
            need(self.book.nodes.get(node.path) is node and node.fd is not None
                 and node.close_state == 'owned' and node.pre and node.expected is node.pre,
                 'resume-sudo-original-custody')
            current = self.book.snapshot(node, 'resume-sudo-post')
            need(not self.errors and self.module._same_snapshot(node.expected, current), 'resume-sudo-original-post')
            node.post = current
        except BaseException:
            self.failed = True
            raise

    def check(self):
        need(self.ready and len(self.book.nodes) == len(self.entries) == 4, 'resume-sudo-check-count')
        for entry in self.entries:
            self.check_one(entry)

    def finish(self):
        # The donor consumes before close and attempts every node. Never retry
        # a consumed original or let a later empty close list erase uncertainty.
        if not self.finished:
            self.finished = True
            try:
                self.close_uncertain = bool(self.book.close_all())
            except BaseException:
                self.close_uncertain = True
        return (not self.close_uncertain and not self.book.budget['uncertain']
                and self.book.result_fd is None
                and all(node.fd is None and node.close_state in ('closed', 'not-opened')
                        for node in self.book.nodes.values()))


def redirect_data(address):
    need(type(address) is str and 0 < len(address) <= 8192, 'p0-artifact-redirect')
    parsed = urllib.parse.urlsplit(address)
    try:
        port = parsed.port
    except ValueError:
        raise Refused('p0-artifact-redirect') from None
    need(parsed.scheme == 'https' and parsed.username is None and parsed.password is None
         and not parsed.fragment and port in (None, 443) and parsed.path.startswith('/')
         and type(parsed.hostname) is str
         and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.blob\.core\.windows\.net', parsed.hostname),
         'p0-artifact-redirect')
    return address


def request_headers(*, authenticated, token):
    result = {'Accept-Encoding': 'identity', 'Connection': 'close',
              'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
    if authenticated:
        need(type(token) is str and 0 < len(token) <= 4096 and '\n' not in token and '\r' not in token, 'p0-service-token')
        result['Authorization'] = 'Bearer ' + token
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def member_stream_complete(stream, info, data_start, central_start, deadline=None):
    """Same original span, real codec EOF and CRC; never ZipExtFile private state."""
    need(type(data_start) is int and type(central_start) is int and data_start >= 0
         and type(info.compress_size) is int and 0 < info.compress_size <= TRANSPORT_LIMIT
         and type(info.file_size) is int and 0 < info.file_size <= MEMBERS[info.filename]
         and data_start + info.compress_size <= central_start, 'collector-public-compressed-span')
    stored = info.compress_type == zipfile.ZIP_STORED
    need(stored or info.compress_type == zipfile.ZIP_DEFLATED, 'collector-public-compression')
    need(not stored or info.compress_size == info.file_size, 'collector-public-stored-size')
    stream.seek(data_start)
    remaining, emitted, crc = info.compress_size, 0, 0
    inflater = None if stored else zlib.decompressobj(-15)
    while remaining:
        if deadline is not None:
            deadline.check()
        wanted = min(65536, remaining)
        data = stream.read(wanted)
        need(type(data) is bytes and len(data) == wanted, 'collector-public-compressed-short')
        remaining -= len(data)
        if stored:
            emitted += len(data)
            crc = zlib.crc32(data, crc)
            continue
        while True:
            if deadline is not None:
                deadline.check()
            output = inflater.decompress(data, 65536)
            produced = len(output)
            emitted += produced
            crc = zlib.crc32(output, crc)
            del output  # No prior output chunk survives the next allocation.
            need(emitted <= info.file_size and not inflater.unused_data,
                 'collector-public-compressed-tail')
            tail = inflater.unconsumed_tail
            if inflater.eof:
                need(not tail and remaining == 0, 'collector-public-compressed-tail')
                break
            consumed = len(data) - len(tail)
            # Header-only compressed input can progress without emitting bytes.
            # A zero-input drain stops when this codec needs the next input.
            if not data and produced == 0:
                break
            need(consumed > 0 or produced > 0, 'collector-public-compressed-progress')
            if tail:
                data = tail
            elif produced == 65536:
                data = b''
            else:
                break
    need(stored or inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail,
         'collector-public-compressed-eof')
    need(emitted == info.file_size and (crc & 0xffffffff) == info.CRC,
         'collector-public-compressed-crc')


def zip_data(body, selected, clock):
    maximum = 256 << 10 if selected['kind'] == 'qualification' else LIMIT
    need(type(body) is bytes and len(body) == selected['bytes'] and 22 <= len(body) <= maximum
         and sha(body) == selected['sha256'], 'p0-zip-original')
    wanted = selected['members']; names = {v['name'] for v in wanted}
    need(len(names) == len(wanted) in (1, 2) and sum(v['bytes'] for v in wanted) <= maximum, 'p0-zip-roster')
    stream = io.BytesIO(body)
    end = struct.unpack('<4s4H2LH', body[-22:])
    need(end[0] == b'PK\x05\x06' and end[1:3] == (0, 0) and end[3] == end[4] == len(wanted)
         and 0 < end[5] <= 16384 and end[6] + end[5] == len(body) - 22 and end[7] == 0, 'p0-zip-central')
    result, span = {}, 0
    with zipfile.ZipFile(stream) as archive:
        infos = sorted(archive.infolist(), key=lambda v: v.header_offset)
        need(len(infos) == len(names) and {v.filename for v in infos} == names, 'p0-zip-roster')
        for info in infos:
            clock.check()
            nominated = next(v for v in wanted if v['name'] == info.filename)
            need(not info.is_dir() and not info.flag_bits & 1 and not info.flag_bits & ~0x080E
                 and stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG)
                 and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                 and info.file_size == nominated['bytes'] and info.header_offset == span,
                 'p0-zip-member')
            stream.seek(info.header_offset); raw = stream.read(30)
            need(len(raw) == 30, 'p0-zip-local')
            local = struct.unpack('<4s5H3L2H', raw)
            need(local[0] == b'PK\x03\x04' and local[2] == info.flag_bits and local[3] == info.compress_type
                 and 0 < local[9] <= 256 and local[10] <= 4096
                 and stream.read(local[9]) == info.filename.encode('utf-8')
                 and len(stream.read(local[10])) == local[10], 'p0-zip-local')
            if not info.flag_bits & 8:
                need(local[6:9] == (info.CRC, info.compress_size, info.file_size), 'p0-zip-local-size')
            else:
                need(local[6] in (0, info.CRC) and local[7] in (0, info.compress_size)
                     and local[8] in (0, info.file_size), 'p0-zip-local-size')
            data_start = stream.tell()
            member_stream_complete(stream, info, data_start, end[6], clock)
            span = data_start + info.compress_size
            if info.flag_bits & 8:
                stream.seek(span); prefix = stream.read(4)
                descriptor = prefix + stream.read(12 if prefix == b'PK\x07\x08' else 8)
                values = struct.unpack('<3L', descriptor[4:] if prefix == b'PK\x07\x08' else descriptor)
                need(values == (info.CRC, info.compress_size, info.file_size), 'p0-zip-descriptor')
                span += len(descriptor)
            with archive.open(info) as member:
                value = member.read(nominated['bytes'] + 1)
                need(type(value) is bytes and len(value) == nominated['bytes'] and member.read(1) == b''
                     and sha(value) == nominated['sha256'], 'p0-zip-member-original')
            result[info.filename] = value
        need(span == end[6], 'p0-zip-unaccounted-bytes')
    clock.check()
    return result


def mount_data(root, parent, filesystem, readonly_flags, mountpoint, device):
    need(stat.S_ISDIR(root.st_mode) and root.st_uid in (0, os.getuid()) and not root.st_mode & 0o022
         and root.st_dev != parent.st_dev and readonly_flags & os.ST_RDONLY
         and type(filesystem) is dict and type(filesystem.get('flags')) is int
         and filesystem['flags'] & 1 and filesystem['flags'] & 0x1000 and not filesystem['flags'] & 0x20
         and filesystem.get('typeName') in ('hfs', 'apfs') and filesystem.get('mountOn') == str(mountpoint)
         and filesystem.get('mountFrom') == device, 'p0-readonly-mount')
    return filesystem


def memory_data(stdout, stderr, returncode, *, page_size, physical_bytes):
    """Apple vm_stat one-shot counters; an observation, not an OS reservation."""
    need(type(returncode) is int and returncode == 0 and type(stdout) is bytes
         and 0 < len(stdout) <= 65536 and stderr == b'', 'p0-memory-original')
    lines = stdout.decode('ascii', 'strict').splitlines()
    need(0 < len(lines) <= 64, 'p0-memory-lines')
    match = re.fullmatch(r'Mach Virtual Memory Statistics: \(page size of ([0-9]{1,7}) bytes\)', lines[0])
    need(match is not None, 'p0-memory-header')
    pagesize = int(match.group(1))
    need(type(page_size) is int and pagesize == page_size and pagesize in (4096, 16384)
         and type(physical_bytes) is int and 0 < physical_bytes < 1 << 50, 'p0-memory-page-size')
    keys = ('Pages free', 'Pages inactive', 'Pages speculative')
    selected = {}
    for line in lines[1:]:
        for key in keys:
            if line.startswith(key + ':'):
                value = re.fullmatch(re.escape(key) + r':\s+([0-9]{1,16})\.', line)
                need(value is not None and key not in selected, 'p0-memory-counter')
                selected[key] = int(value.group(1))
    need(set(selected) == set(keys), 'p0-memory-counter')
    result = pagesize * sum(selected.values())
    need(0 < result <= physical_bytes, 'p0-memory-bound')
    return {'availableEstimateBytes': result, 'pageSize': pagesize,
            'counters': selected, 'physicalMemoryBytes': physical_bytes, 'osMemoryReservation': False, 'peakRssQualified': False}


RESOURCE_BYTE_KEYS = ('availableMemoryEstimateBytes','requiredMemoryBytes','availableDiskBytes','requiredDiskBytes')


def resource_admission_data(available_memory,required_memory,available_disk,required_disk):
    values = (available_memory,required_memory,available_disk,required_disk)
    need(all(type(v) is int and 0 <= v <= (1 << 53)-1 for v in values)
         and required_memory > 0 and required_disk > 0, 'resume-resource-diagnostic-bound')
    return {**dict(zip(RESOURCE_BYTE_KEYS,values)),
            'memorySufficient':available_memory >= required_memory,
            'diskSufficient':available_disk >= required_disk,
            'osMemoryReservation':False,'peakRssQualified':False}


def resource_projection_data(value):
    """An exact finite observation, never reservation or operation success."""
    if type(value) is not dict or set(value) != set(RESOURCE_BYTE_KEYS) | {
            'memorySufficient','diskSufficient','osMemoryReservation','peakRssQualified'}:
        return None
    if any(type(value[k]) is not bool for k in ('memorySufficient','diskSufficient','osMemoryReservation','peakRssQualified')):
        return None
    try: expected = resource_admission_data(*(value[k] for k in RESOURCE_BYTE_KEYS))
    except Refused: return None
    return expected if value == expected else None


def acquisition_memory_requirement(retained):
    """Bound immutable acquisition copies, not unentered codec maxima."""
    need(type(retained) is int and 0 <= retained <= 1 << 30, 'resume-memory-retained-bound')
    return 6 * (ORIGIN['artifactBytes'] + ORIGIN['imageBytes']) + (16 << 20) + retained + (512 << 20) + (1 << 30)


def post_acquisition_memory_requirement(retained):
    """After ZIP parse/POST returns, only its acquisition-copy allowance is dead.

    Keep all image copies and reserves; actual later samples still admit/refuse.
    """
    return acquisition_memory_requirement(retained) - 6 * ORIGIN['artifactBytes']


def allocation_memory_requirement(base, live, packed, output):
    # Packed slices and zlib unused/unconsumed copies may coexist; growth and
    # final immutable output can coexist too. Do not credit either as released.
    need(type(base) is int and 0 < base < 1 << 53
         and all(type(value) is int and 0 <= value <= 8 * LIMIT for value in (live, packed))
         and type(output) is int and 0 <= output <= LIMIT, 'resume-allocation-byte-bound')
    required = base + live + 3 * packed + 2 * (output + 1) + (16 << 20)
    need(required < 1 << 53, 'resume-allocation-byte-bound')
    return required


def host_memory_data(host, clock):
    # Existing authenticated DarwinAPI's read-only sysctlbyname ABI only.
    values = {}
    for name, scalar in ((b'hw.pagesize', ctypes.c_int), (b'hw.memsize', ctypes.c_uint64)):
        clock.check(); value = scalar(); size = ctypes.c_size_t(ctypes.sizeof(value))
        returned = host.library.sysctlbyname(name, ctypes.byref(value), ctypes.byref(size), None, 0)
        need(returned == 0 and size.value == ctypes.sizeof(value) and value.value > 0, 'p0-memory-host-original')
        values[name] = value.value
        clock.check()
    return values[b'hw.pagesize'], values[b'hw.memsize']


def load_module(name, path, body):
    need(name not in sys.modules, 'p0-source-module-collision')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(body, str(path), 'exec'), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def bootstrap_originals(root):
    # Bootstrap the checkout-owned passive class before its own resource book.
    relative = 'desktop/tools/macos_e2_native_fixture.py'
    fd = os.open(root / relative, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    primary = None
    try:
        before = identity(os.fstat(fd))
        need(stat.S_ISREG(before[2]) and before[3] == os.getuid() and before[5] == 1 and not before[2] & 0o022
             and 0 < before[6] <= SOURCE_MODULE_LIMIT, 'p0-bootstrap-original')
        size = before[6]
        body = os.pread(fd, size + 1, 0)
        need(len(body) == size and not os.pread(fd, 1, size) and identity(os.fstat(fd)) == before
             == identity(os.stat(root / relative, follow_symlinks=False)), 'p0-bootstrap-source')
    except BaseException as error:
        primary = error
        raise
    finally:
        consumed, fd = fd, None  # Consumed before close; never retry.
        try:
            os.close(consumed)
        except BaseException:
            if primary is None: raise Refused('p0-bootstrap-close-unknown') from None
            BaseException.add_note(primary, 'p0-bootstrap-close-unknown')
    return load_module('_mrk_p0_originals', root / relative, body).Originals


def metadata_data(run, job, artifact, row, role, target):
    need(role == 'carrier' and target == TARGETS[0] and row == ORIGIN, 'resume-fixed-nomination')
    need(type(run) is dict and type(job) is dict and type(artifact) is dict
         and type(run.get('id')) is int and str(run['id']) == row['runId']
         and type(run.get('run_attempt')) is int and str(run['run_attempt']) == row['runAttempt']
         and run.get('head_sha') == row['source'] and run.get('head_branch') == 'verify/desktop-macos-installed'
         and run.get('path') == WORKFLOW and run.get('workflow_id') == WORKFLOW_ID
         and run.get('status') == 'completed' and run.get('conclusion') == 'cancelled'
         and type(run.get('repository')) is dict and run['repository'].get('full_name') == REPOSITORY,
         'resume-producer-run')
    steps = job.get('steps')
    need(type(job.get('id')) is int and str(job['id']) == row['jobId']
         and job.get('run_id') == run['id'] and job.get('head_sha') == row['source']
         and job.get('status') == 'completed' and job.get('conclusion') == 'failure'
         and type(steps) is list and 54 <= len(steps) <= 256
         and all(type(v) is dict and v.get('status') == 'completed' for v in steps), 'resume-producer-job')
    for number, name in ((51, 'Standard Installer only is privileged; never execute the app or Python as root'),
                         (52, 'Notarize, staple and verify only the final user image'),
                         (53, 'Stage only the finalized ordinary image as an unqualified P0 carrier input'),
                         (54, 'Retain one finalized DMG and its finite descriptor for later independent P0 qualification')):
        selected = [v for v in steps if v.get('number') == number]
        need(len(selected) == 1 and selected[0].get('name') == name
             and selected[0].get('conclusion') == 'success', 'resume-producer-stage-closed')
    need(type(artifact.get('id')) is int and str(artifact['id']) == row['artifactId']
         and artifact.get('name') == 'mobile-release-kit-macos26-' + target + '-p0-carrier-input-' + row['source'] + '-' + row['runId'] + '-' + row['runAttempt']
         and artifact.get('expired') is False and type(artifact.get('size_in_bytes')) is int
         and artifact['size_in_bytes'] == row['artifactBytes'] and artifact.get('digest') == 'sha256:' + row['artifactSha256']
         and type(artifact.get('workflow_run')) is dict and artifact['workflow_run'].get('id') == run['id']
         and artifact['workflow_run'].get('head_sha') == row['source']
         and artifact['workflow_run'].get('head_branch') == run['head_branch'], 'resume-artifact-metadata')
    return row


def origin_public_data(body):
    need(type(body) is bytes and len(body) == 64405 and sha(body) == ORIGIN['qualificationEvidenceSha256'], 'resume-public-source-pin')
    value = decode(body)
    need(type(value) is dict and value.get('schemaVersion') == 1 and type(value['schemaVersion']) is int
         and value.get('kind') == 'mrk-public-verification-evidence-v1'
         and value.get('diagnosticOnly') is True and value.get('productReady') is False
         and (value.get('source'), value.get('workflowSource'), value.get('runId'), value.get('runAttempt'), value.get('target'))
             == (ORIGIN['source'], ORIGIN['source'], ORIGIN['runId'], ORIGIN['runAttempt'], TARGETS[0])
         and value.get('sourceInventory', {}).get('tree') == ORIGIN['tree'], 'resume-public-source-join')
    for name in ('finalize-package', 'package-install', 'finalize-image'):
        phase = value.get('phases', {}).get(name)
        need(type(phase) is dict and phase.get('receiptState') == 'observed' and phase.get('recordedPassed') is True
             and phase.get('correlationMatches') is True and phase.get('failure') is None
             and phase.get('callerStatus') == {'receiptState': 'observed', 'returncode': 0}
             and all(phase.get(k) is True for k in ('originalClosesKnown', 'targetRetired', 'outerFinalityRequired')),
             'resume-original-phase-finality')
        calls = phase.get('originalCalls', {})
        need(calls.get('unclassifiedCount') == 0 and type(calls.get('calls')) is list and calls['calls']
             and all(v.get('entered') is True and v.get('returned') is True and v.get('capturesSettled') is True
                 and type(v.get('returncode')) is int and v['returncode'] in ((0, 1) if v.get('role') in ('installer-log-cursor', 'installer-log-capture') else (0,))
                 for v in calls['calls']), 'resume-original-phase-calls')
        need(type(phase.get('credentialContexts')) is list and all(all(v.get(k) is True for k in ('closed', 'retired', 'searchRestored', 'defaultUnchanged'))
             for v in phase['credentialContexts']), 'resume-original-credential-finality')
    final = value['phases']['finalize-image']['finalImage']
    need(type(final) is dict and final.get('status') == 'Accepted'
         and all(final.get(k) is True for k in ('actualDiskImagePolicyAssessment', 'actualImageVerification', 'actualStaplerValidation',
             'assessmentSubsystemEnabledBefore', 'finalMountOriginalsMatch', 'finalMountReadOnly', 'originalMountDetached', 'sha256Compared', 'strictSignatureBeforeAndAfter'))
         and (final['imageBytes'], final['imageSha256']) == (ORIGIN['imageBytes'], ORIGIN['imageSha256'])
         and (final['packageBytes'], final['packageSha256']) == (ORIGIN['package']['bytes'], ORIGIN['package']['sha256'])
         and (final['descriptorBytes'], final['descriptorSha256']) == (ORIGIN['descriptor']['bytes'], ORIGIN['descriptor']['sha256'])
         and (final['signatureBytes'], final['signatureSha256']) == (ORIGIN['signature']['bytes'], ORIGIN['signature']['sha256']), 'resume-final-image-source-join')
    # deliveries.preview really is absent in this public original. This separate
    # authority admits only successful builder stages, NEVER a whole-job/P0 pass.
    return value


def fixed_members(body, clock):
    need(type(body) is bytes and len(body) == ORIGIN['artifactBytes'] and sha(body) == ORIGIN['artifactSha256'], 'resume-outer-zip-pin')
    with zipfile.ZipFile(io.BytesIO(body)) as z:
        infos = z.infolist()
        need(len(infos) == 2 and {v.filename for v in infos} == {'MobileReleaseKit.dmg', 'PREVIEW.json'}, 'resume-flat-two')
        wanted = []
        for info in infos:
            clock.check()
            need(not info.is_dir() and type(info.file_size) is int and 0 < info.file_size <= MEMBERS[info.filename], 'resume-member-bound')
            if info.filename == 'MobileReleaseKit.dmg':
                need(info.file_size == ORIGIN['imageBytes'], 'resume-image-size')
                digest = ORIGIN['imageSha256']
            else:
                # Outer immutable SHA authenticates this finite metadata member.
                # Its observed digest is correspondence, not a guessed nomination.
                with z.open(info) as member:
                    data = member.read(16385)
                    need(type(data) is bytes and len(data) == info.file_size and member.read(1) == b'', 'resume-preview-bound')
                digest = sha(data)
            wanted.append({'name': info.filename, 'bytes': info.file_size, 'sha256': digest})
    return zip_data(body, {'kind': 'carrier', 'bytes': len(body), 'sha256': ORIGIN['artifactSha256'], 'members': wanted}, clock)


def preview_data(body, stager):
    need(type(body) is bytes and 0 < len(body) <= 16384, 'resume-preview-size')
    value = decode(body)
    need(type(value) is dict and value.get('schemaVersion') == 2 and type(value['schemaVersion']) is int
         and (value.get('sourceCommit'), value.get('sourceTree'), value.get('runId'), value.get('runAttempt'), value.get('platform'), value.get('workflow'))
             == (ORIGIN['source'], ORIGIN['tree'], ORIGIN['runId'], ORIGIN['runAttempt'], 'macOS26-arm64', WORKFLOW)
         and value.get('scope') == 'normal-macos-early-preview' and value.get('packageRole') == 'ordinary-image'
         and value.get('instrumented') is False
         and all(value.get(k) == 'passed' for k in ('normalBuild', 'packageAudit', 'installationReadback'))
         and (value.get('packageSha256'), value.get('packageSize')) == (ORIGIN['package']['sha256'], ORIGIN['package']['bytes'])
         and (value.get('distributionSha256'), value.get('distributionBytes')) == (ORIGIN['imageSha256'], ORIGIN['imageBytes'])
         and value.get('descriptorSha256') == ORIGIN['descriptor']['sha256'] and value.get('signatureSha256') == ORIGIN['signature']['sha256']
         and all(value.get(k) is True for k in ('originalInstallerReturnedZero', 'originalPackageGroupReturnedZero', 'originalObservationMountDetached',
             'originalImageFinalizationReturnedZero', 'originalFinalImageMountDetached', 'finalImageScopedNotarizationObserved'))
         and all(value.get(k) is False for k in ('fullM2Qualified', 'maintenanceQualified', 'fullUIQualified', 'distributionQualified', 'productReady'))
         and value.get('automaticWindowOpen') == 'unexecuted' and value.get('normalQuit') == 'unexecuted', 'resume-preview-original-correspondence')
    need(stager.maintenance_hex(value.get('runtimeManifestSha256'), 64)
         and stager.maintenance_hex(value.get('installerInventorySha256'), 64), 'resume-preview-inventory-bindings')
    return value

def pinned_ca_request_data(cfg, root):
    need(type(cfg['caPath']) is str and cfg['caPath'] == str(root / TLS_CA_PATH)
         and cfg['caSha256'] == TLS_CA_SHA256, 'p0-pinned-ca-route')


def tls_context(ca):
    context = ssl.create_default_context(cadata=ca.decode('ascii', 'strict'))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    need(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED, 'p0-tls-policy')
    return context


def acquisition_main():
    """Fixed child; parent supplies exact retained SOURCE via authenticated -c.

    Only work-directory/output/CA originals are newly opened in this child;
    full work/source/CA ancestor custody stays with the original waiting parent.
    Never print signed URLs, headers, tokens, CA contents or native captures.
    """
    cfg = decode(os.environ['MRK_P0_REQUEST'].encode('ascii'))
    need(type(cfg) is dict and set(cfg) == {'row', 'role', 'target', 'work', 'workIdentity', 'caPath', 'caSha256', 'endpoint'}, 'p0-child-request')
    role, row = cfg['role'], cfg['row']
    need(role in ('qualification', 'carrier') and cfg['target'] in TARGETS
         and type(cfg['endpoint']) is int and time.monotonic_ns() < cfg['endpoint']
         and type(cfg['work']) is str and re.fullmatch(r'/Users/runner/work/_temp/mrk-macos-installed\.[A-Za-z0-9]{8}/resume-carrier', cfg['work']) is not None
         and str(Path(cfg['work'])) == os.path.normpath(cfg['work']), 'p0-child-admission')
    endpoint = cfg['endpoint'] / 1e9
    token = os.environ['MRK_P0_READ_TOKEN']
    phase, response, ca_fd, root_fd, output_fd = 'trust', None, None, None, None
    errors, primary = [], None
    try:
        pinned_ca_request_data(cfg, Path(__file__).absolute().parents[2])
        ca_fd = os.open(cfg['caPath'], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        ca_before = identity(os.fstat(ca_fd))
        need(stat.S_ISREG(ca_before[2]) and ca_before[3] in (0, os.getuid()) and ca_before[5] == 1
             and not ca_before[2] & 0o022 and 0 < ca_before[6] <= 2 << 20
             and identity(os.stat(cfg['caPath'], follow_symlinks=False)) == ca_before, 'p0-ca-original')
        ca = os.pread(ca_fd, ca_before[6] + 1, 0)
        need(len(ca) == ca_before[6] and sha(ca) == cfg['caSha256']
             and identity(os.fstat(ca_fd)) == ca_before, 'p0-ca-pin')
        context = tls_context(ca)
        consumed, ca_fd = ca_fd, None; os.close(consumed)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
        root_fd = os.open(cfg['work'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        root_before = identity(os.fstat(root_fd))[:5]
        need(stat.S_ISDIR(root_before[2]) and stat.S_IMODE(root_before[2]) == 0o700
             and root_before[3:5] == (os.getuid(), os.getgid())
             and type(cfg['workIdentity']) is list and len(cfg['workIdentity']) == 5
             and all(type(v) is int for v in cfg['workIdentity'])
             and list(root_before) == cfg['workIdentity']
             and identity(os.stat(cfg['work'], follow_symlinks=False))[:5] == root_before, 'p0-child-work-original')
        def point():
            need(time.monotonic() < endpoint
                 and identity(os.fstat(root_fd))[:5] == root_before
                 == identity(os.stat(cfg['work'], follow_symlinks=False))[:5], 'p0-child-post-deadline')
        def request(url, authenticated):
            point()
            req = urllib.request.Request(url, headers=request_headers(authenticated=authenticated, token=token), method='GET')
            try:
                return opener.open(req, timeout=max(.01, min(10, endpoint - time.monotonic())))
            except urllib.error.HTTPError as error:
                return error
        def headers(value):
            pairs_list = list(value.headers.items())
            need(len(pairs_list) <= 64, 'p0-response-headers')
            result = {}
            for key, item in pairs_list:
                key = key.lower()
                need(key not in result and len(key) <= 256 and type(item) is str and len(item) <= 8192, 'p0-response-headers')
                result[key] = item
            return result
        def metadata(endpoint_path):
            nonlocal response
            response = request('https://api.github.com/repos/' + REPOSITORY + endpoint_path, True)
            h = headers(response)
            need(response.code == 200 and 'location' not in h and h.get('content-encoding', 'identity') == 'identity', 'p0-metadata-response')
            body = bytearray()
            while True:
                point(); block = response.read(min(65536, (256 << 10) + 1 - len(body)))
                need(type(block) is bytes, 'p0-metadata-bytes')
                body.extend(block); need(len(body) <= 256 << 10, 'p0-metadata-bound')
                if not block: break
            consumed, response = response, None; consumed.close()
            return decode(bytes(body))
        phase = 'closed-metadata'
        run = metadata('/actions/runs/' + row['runId'] + '/attempts/' + row['runAttempt'])
        job = metadata('/actions/jobs/' + row['jobId'])
        selected = row['qualificationArtifact'] if role == 'qualification' else row
        artifact = metadata('/actions/artifacts/' + selected['artifactId'])
        metadata_data(run, job, artifact, row, role, cfg['target'])
        phase = 'artifact'
        response = request('https://api.github.com/repos/' + REPOSITORY + '/actions/artifacts/' + selected['artifactId'] + '/zip', True)
        h = headers(response)
        need(response.code == 302, 'p0-artifact-api-redirect')
        address = redirect_data(h.get('location'))
        consumed, response = response, None; consumed.close()
        response = request(address, False)  # Authorization is never forwarded.
        h = headers(response)
        need(response.code == 200 and 'location' not in h and h.get('content-encoding', 'identity') == 'identity'
             and ('content-length' not in h or h['content-length'] == str(selected['artifactBytes'])), 'p0-artifact-response')
        name = ('arm64' if cfg['target'] == TARGETS[0] else 'intel') + '-' + role + '.zip'
        output_fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root_fd)
        count, digest = 0, hashlib.sha256()
        while True:
            point(); amount = min(65536, selected['artifactBytes'] + 1 - count)
            block = response.read(amount)
            need(type(block) is bytes and len(block) <= amount, 'p0-artifact-response-bytes')
            count += len(block); need(count <= selected['artifactBytes'], 'p0-artifact-bound')
            if not block: break
            digest.update(block); view = memoryview(block)
            while view:
                point(); written = os.write(output_fd, view); need(written > 0, 'p0-artifact-write')
                view = view[written:]
        need(count == selected['artifactBytes'] and digest.hexdigest() == selected['artifactSha256'], 'p0-artifact-digest')
        consumed, response = response, None; consumed.close()
        os.fsync(output_fd); before = identity(os.fstat(output_fd))
        need(stat.S_ISREG(before[2]) and stat.S_IMODE(before[2]) == 0o600 and before[3:6] == (os.getuid(), os.getgid(), 1)
             and before[6] == count and identity(os.stat(name, dir_fd=root_fd, follow_symlinks=False)) == before, 'p0-artifact-original')
        observed = hashlib.sha256()
        for at in range(0, count, 65536):
            point(); data = os.pread(output_fd, min(65536, count - at), at)
            need(len(data) == min(65536, count - at), 'p0-artifact-readback')
            observed.update(data)
        need(not os.pread(output_fd, 1, count) and observed.hexdigest() == selected['artifactSha256']
             and identity(os.fstat(output_fd)) == before
             == identity(os.stat(name, dir_fd=root_fd, follow_symlinks=False)), 'p0-artifact-post')
        point()
        result = {'schemaVersion': 1, 'role': role, 'target': cfg['target'], 'bytes': count,
                  'sha256': selected['artifactSha256'], 'closedMetadataMatched': True}
    except BaseException as error:
        primary = error
        raise
    finally:
        if response is not None:
            consumed, response = response, None
            try: consumed.close()
            except BaseException: errors.append('p0-response-close')
        for fd in (output_fd, root_fd, ca_fd):
            if fd is not None:
                try: os.close(fd)  # One consuming attempt; never retry an unknown close.
                except BaseException: errors.append('p0-child-original-close')
        if errors:
            if primary is None: raise Refused('p0-child-close-unknown')
            BaseException.add_note(primary, 'p0-child-close-unknown')
    result['originalClosesKnown'] = True
    return result


def original_release_readback_data(mounted, inventory, *, target):
    # Called only after the fixed held carrier/member and native signature
    # owners succeeded. This DATA record is neither P0 nor signature authority.
    need(type(mounted) is dict and target == TARGETS[0] == mounted.get('target')
         and all(mounted.get(key) == ORIGIN[key] for key in ('source', 'tree', 'runId', 'runAttempt', 'jobId',
                 'artifactId', 'artifactSha256', 'package', 'descriptor', 'signature')),
         'resume-original-release-provenance')
    release = mounted['release']
    need(type(release) is dict and all(release.get(key) == ORIGIN[origin] for key, origin in
         (('sourceCommit', 'source'), ('packageVersion', 'packageVersion'), ('release', 'release')))
         and release.get('packageSha256') == ORIGIN['package']['sha256']
         and type(inventory) is bytes and 0 < len(inventory) <= 1024 * 1024
         and mounted['inventory'] == {'name': 'install-inventory.json', 'bytes': len(inventory), 'sha256': sha(inventory)}
         and mounted['inventory']['sha256'] == release.get('inventorySha256')
         and mounted['signingPolicy']['sha256'] == release.get('signingPolicySha256'), 'resume-original-release-binding')
    return {'schemaVersion': 1, 'purpose': 'fixed-ce644-arm-original-release-readback', 'target': target,
            'release': dict(release), 'descriptor': {key: mounted['descriptor'][key] for key in ('bytes', 'sha256')},
            'signature': {key: mounted['signature'][key] for key in ('bytes', 'sha256')},
            'inventory': {key: mounted['inventory'][key] for key in ('bytes', 'sha256')}}


def scripts_archive_data(packed, stager, live, allocation_budget=None):
    if packed[:2] != b'\x1f\x8b':
        return packed
    if allocation_budget is None:
        return stager.inflate(packed, LIMIT, gzip=True)
    need(len(packed) >= 18, 'resume-scripts-gzip-header')
    expanded = struct.unpack_from('<I', packed, len(packed) - 4)[0]
    need(expanded <= LIMIT, 'resume-scripts-expanded-bound')
    allocation_budget('scripts', live, len(packed), expanded)
    archive = stager.inflate(packed, expanded, gzip=True)
    need(len(archive) == expanded, 'resume-scripts-expanded-size')
    return archive


def mounted_data(originals, row, target, stager, *, allocation_budget=None):
    """Actual unchanged package parsers; inventory digest precedes observed size."""
    need(type(originals) is dict and set(originals) == {'Install.pkg', 'producer.json', 'producer.sig'}
         and all(type(v) is tuple and len(v) == 2 and type(v[0]) is bytes and type(v[1]) is int for v in originals.values()), 'enrollment-mounted-roster')
    bodies = {k: v[0] for k, v in originals.items()}
    for key in ('package', 'descriptor', 'signature'):
        selected = row[key]; body = bodies[selected['name']]
        need(type(body) is bytes and len(body) == selected['bytes'] and sha(body) == selected['sha256'], 'enrollment-mounted-original')
    # Caller separately proves root/UID/nlink/readonly. Never manufacture modes.
    stager.distribution_layout_data(list(originals), 'Install.pkg', bodies, originals)
    descriptor = stager.maintenance_producer_data(bodies['producer.json'], target=target)
    releases = descriptor['releaseSet']; release = releases['current']
    need(not releases['acceptedPredecessors'] and len(descriptor['signingPolicies']) == 1
         and all(release[k] == row[v] for k, v in (('sourceCommit', 'source'), ('runtimeManifestSha256', 'runtimeManifestSha256'),
                 ('inventorySha256', 'inventorySha256'), ('packageVersion', 'packageVersion'), ('release', 'release')))
         and release['packageSha256'] == row['package']['sha256'], 'enrollment-release-original')
    policy = descriptor['signingPolicies'][0]
    need(policy['sha256'] == release['signingPolicySha256'] and all(policy['policy'][k] == v for k, v in row['signingIdentity'].items()), 'enrollment-policy-original')
    selection = stager.BuildSelection(target, row['packageVersion'], row['release'])
    members = (stager.install_product_members(bodies['Install.pkg']) if allocation_budget is None else
        stager.install_product_members(bodies['Install.pkg'], allocation_budget=allocation_budget))
    outer_retained = sum(len(value) for value in members.values())
    def nested_budget(phase, live, packed, output):
        if allocation_budget is not None:
            allocation_budget(phase, outer_retained + live, packed, output)
    if stager.INSTALL_COMPONENT in members:
        component = (stager.xar_members(members[stager.INSTALL_COMPONENT]) if allocation_budget is None else
            stager.xar_members(members[stager.INSTALL_COMPONENT], allocation_budget=nested_budget))
    else:
        component = {k: members[stager.INSTALL_COMPONENT + '/' + k] for k in ('PackageInfo', 'Scripts')}
    need(set(component) == {'PackageInfo', 'Scripts'}, 'enrollment-product-component')
    del members
    outer_retained = 0
    stager.package_info(component['PackageInfo'], selection=selection)
    packed = component['Scripts']
    component_retained = sum(len(value) for value in component.values())
    archive = scripts_archive_data(packed, stager, outer_retained + component_retained, allocation_budget)
    def cpio_budget(phase, live, packed_bytes, output):
        if allocation_budget is not None:
            allocation_budget(phase, outer_retained + component_retained + live, packed_bytes, output)
    scripts = (stager.cpio_members(archive) if allocation_budget is None else
        stager.cpio_members(archive, allocation_budget=cpio_budget))
    key = 'input/' + stager.INSTALLATION_INVENTORY_NAME
    need(key in scripts and type(scripts[key][0]) is bytes and scripts[key][1] == 0o444, 'enrollment-original-inventory')
    inventory = scripts[key][0]
    rows = stager.observation_inventory_bytes(inventory, row['inventorySha256'], row['runtimeManifestSha256'], selection=selection)
    result = {'schemaVersion': 1, 'kind': 'mrk-p0-readonly-enrollment-data-v1', 'target': target,
            'source': row['source'], 'tree': row['tree'], 'runId': row['runId'], 'runAttempt': row['runAttempt'],
            'jobId': row['jobId'], 'artifactId': row['artifactId'], 'artifactSha256': row['artifactSha256'],
            'qualificationEvidenceSha256': row['qualificationEvidenceSha256'], 'members': row['members'],
            'package': row['package'], 'descriptor': row['descriptor'], 'signature': row['signature'],
            'inventory': {'name': stager.INSTALLATION_INVENTORY_NAME, 'bytes': len(inventory), 'sha256': sha(inventory)},
            'inventoryDocument': stager.decode(inventory), 'release': release, 'signingPolicy': policy,
            'inventoryFiles': len(rows), 'inventoryPayloadBytes': sum(v['size'] for v in rows.values()),
            'nativeQualificationInferred': False, 'updateActivated': False, 'productReady': False}
    return result, inventory


def producer_message_data(descriptor):
    # Native install_producer.m and Rust message_data sign the domain (one NUL)
    # followed by the exact original descriptor bytes, never reserialized JSON.
    need(type(descriptor) is bytes and 0 < len(descriptor) <= 64 * 1024,
         'resume-producer-message-bound')
    return b'MobileReleaseKit-package-producer-v2\0' + descriptor


def transport_path_data(run, attempt):
    need(all(type(v) is str and re.fullmatch(r'[1-9][0-9]{0,19}', v)
             for v in (run, attempt)), 'resume-transport-context')
    context = '\n'.join((run, attempt, TARGETS[0], 'fixed-carrier-resume'))
    return Path('/Volumes') / ('MRK-Install-' + sha(context.encode('ascii'))[:32])


def transport_transition_data(before, after, previous, current, name, member, *, present):
    # Only our observed attach/detach may change directory bookkeeping. The
    # protected identity, ACL/flags/mount and every unrelated name stay fixed.
    need(current[0][:5] == previous[0][:5] and current[1:] == previous[1:],
         'resume-transport-parent-authority')
    wanted = dict(before)
    if present:
        need(name not in wanted, 'resume-transport-collision')
        wanted[name] = member
    else:
        need(wanted.get(name) == member, 'resume-transport-original-mount')
        del wanted[name]
    need(after == wanted, 'resume-transport-exact-namespace-effect')


def fresh_installer_request_data(before, after):
    # Install.pkg generates its request inside the native parent. Only this
    # fresh original0 and a one-entry delta in the protected export namespace
    # may select it; neither the old carrier nor a caller-supplied receipt can.
    need(type(before) is dict and not before and type(after) is dict and len(after) == 1,
         'resume-fresh-installer-result-delta')
    request = next(iter(after))
    need(type(request) is str and re.fullmatch(r'[0-9a-f]{32}', request)
         and request != '0' * 32, 'resume-fresh-installer-request')
    return request


class Resume:
    def __init__(self, root, work, clock, factory, *, quota=None):
        self.root, self.work, self.clock = root, work, clock
        self.quota = OriginalQuota() if quota is None else quota
        self.outer = self.quota.book(factory)
        self.factory = factory
        self.calls, self.sources, self.private, self.results = [], [], {}, []
        self.output_bytes = 0
        self.public = {}
        self.expected_public = ()
        self.parent = self.quota.call(self.outer, 'directory', work)


    def fresh_book(self, *, transport=False):
        book = self.quota.book(self.factory)
        # Borrow ONLY authenticated outer ancestor originals, never a mount leaf.
        need(not book.entries and not book.directories, 'p0-fresh-book-shape')
        self.outer.check()
        base = Path('/Volumes') if transport else self.work
        borrowed = {path: entry for path, entry in self.outer.directories.items()
                    if path == base or path in base.parents}
        need(base in borrowed and all(entry['kind'] == 'directory' and entry['fd'] is not None
             and not entry['closed'] for entry in borrowed.values()), 'p0-borrowed-ancestor-admission')
        book.directories.update(borrowed)
        book._p0_borrowed = tuple(borrowed.items())
        return book


    def point(self):
        self.clock.check(); self.quota.check()


    def source(self, relative, size, digest=None, *, uid=None):
        entry, body = self.quota.call(self.outer, 'file', self.root / relative, size, uid=os.getuid() if uid is None else uid)
        need(digest is None or sha(body) == digest, 'p0-source-pin')
        self.sources.append((entry, body))
        return body


    def command(self, role, argv, maximum, *, env=None):
        need(role in ('memory', 'acquire-carrier', 'attach', 'detach', 'producer-key', 'producer-signature', 'installer', 'entry-signature', 'payload-signature'), 'p0-command-role')
        self.point(); timeout = self.clock.seconds(maximum)
        limit = 256 * 1024 if role == 'installer' else 65536
        row = {'role': role, 'entered': True, 'returned': False, 'capturesSettled': False,
               'timeoutSeconds': timeout, 'outputLimitBytes': limit}
        self.calls.append(row)
        STATE['lastRole'] = role
        try:
            result = self.owner.run_owned(argv, environ=self.environment if env is None else env, cwd=self.work,
                                          timeout=timeout, capture=True, text=False, output_limit=limit, cleanup=self.clock.finality)
        except BaseException as error:
            row['contained'] = getattr(error, 'contained', None) if type(getattr(error, 'contained', None)) is bool else None
            row['cleanupComplete'] = getattr(error, 'cleanup_complete', None) if type(getattr(error, 'cleanup_complete', None)) is bool else None
            raise
        need(result.args == argv and type(result.returncode) is int and type(result.stdout) is bytes
             and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= limit, 'p0-original-command')
        row.update(returned=True, capturesSettled=True, returncode=result.returncode)
        self.point()
        return result


    def allocation_budget(self, phase, live, packed, output):
        need(phase in ('install-product-toc', 'install-product-member', 'xar-toc', 'xar-member',
              'scripts', 'cpio-window', 'cpio-slice'), 'resume-allocation-role')
        required = allocation_memory_requirement(self.memory_base, live, packed, output)
        self.clock.check()
        if phase == 'cpio-slice':
            # One phase envelope funds all monotone, nonoverlapping slices.
            # Not an OS reservation; never spawn a command for each file.
            need(self.cpio_window is not None and packed == output == 0
                 and required <= self.cpio_window, 'resume-cpio-allocation-window')
            return
        if phase == 'cpio-window':
            need(self.cpio_window is None and packed == output == 0, 'resume-cpio-window-once')
        self.allocation_samples += 1
        need(self.allocation_samples <= 13, 'resume-allocation-sample-bound')
        previous_phase = STATE['phase']
        STATE['phase'] = 'resource-admission'
        call = self.command('memory', ['/usr/bin/vm_stat'], 10)
        page_size, physical = host_memory_data(self.host, self.clock)
        memory = memory_data(call.stdout, call.stderr, call.returncode, page_size=page_size, physical_bytes=physical)
        disk = os.fstatvfs(self.parent['fd'])
        STATE['resourceAdmission'] = resource_admission_data(memory['availableEstimateBytes'], required,
            disk.f_bavail * disk.f_frsize, self.required_disk)
        need(STATE['resourceAdmission']['memorySufficient'], 'resume-resource-memory-admission')
        need(STATE['resourceAdmission']['diskSufficient'], 'resume-resource-disk-admission')
        if phase == 'cpio-window':
            self.cpio_window = required
        STATE['phase'] = previous_phase


    def publish_image(self, path, image):
        # Donor publish's 128 MiB public-output cap is deliberately unchanged.
        # This fixed owned DMG alone uses the same prequoted original book,
        # exact register/read/close semantics and bounded streaming copy.
        need(path in (self.work / 'arm64.dmg', self.work / 'intel.dmg')
             and type(image) is bytes and 0 < len(image) <= LIMIT, 'p0-image-copy-admission')
        parent = self.quota.call(self.outer, 'directory', path.parent)
        self.quota.reserve(1)  # Before the only new os.open/register allocation.
        before = len(self.outer.entries)
        fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent['fd'])
        entry = self.outer.register(fd, path, 'output')
        need(len(self.outer.entries) - before == 1, 'p0-image-copy-original-quote')
        entry['parent'] = parent
        at = 0
        while at < len(image):
            self.clock.check()
            # This one owned output is still being written and has no stable
            # snapshot yet. All other retained originals stay under exact POST.
            for book in self.quota.books:
                for held in book.entries:
                    if held is not entry and held['fd'] is not None: book.check_one(held)
            view = memoryview(image)[at:at + 65536]
            while view:
                self.clock.check()
                count = os.write(fd, view)
                need(0 < count <= len(view), 'p0-image-copy-write')
                view = view[count:]; at += count
        os.fchmod(fd, 0o444); os.fsync(fd)
        entry['identity'] = identity(os.fstat(fd))
        need(entry['identity'][3:6] == (os.getuid(), os.getgid(), 1)
             and entry['identity'][6] == len(image) and stat.S_IMODE(entry['identity'][2]) == 0o444
             and self.outer.read(entry) == image, 'p0-image-copy-readback')
        self.outer.close(entry)
        need(entry['closed'], 'p0-image-copy-close')
        self.point()


    def fresh_directory(self, parent, name):
        self.point(); self.quota.reserve(1)  # BEFORE mkdir or donor open.
        os.mkdir(name, 0o700, dir_fd=parent['fd'])
        before = len(self.outer.entries)
        entry = self.outer.directory(parent['path'] / name)
        need(len(self.outer.entries) - before == 1 and os.listdir(entry['fd']) == [], 'resume-fresh-directory')
        return entry

    def publish_owned(self, path, data, mode=0o444):
        self.point()
        self.quota.call(self.outer, 'publish', path, data, mode=mode)
        entry = self.outer.entries[-1]
        need(entry['closed'] and not self.outer.errors and entry['identity'][6] == len(data), 'resume-publication-close')
        self.private[str(path.relative_to(self.work))] = entry['identity']
        return entry

    def transport_facts(self, entry):
        # Same protected /Volumes policy as the existing packaging transport.
        self.point(); self.outer.check_one(entry)
        info = os.fstat(entry['fd'])
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
             and not info.st_mode & 0o7022, 'resume-transport-protected-parent')
        acl = self.host_module._acl_snapshot(self.host.library, entry['fd'], self.host_module.full9(info))
        need(acl.get('empty') is True and acl.get('phase') == 0 and acl.get('filesecFreeReturned') is True
             and acl.get('aclFreeResult') in (None, 0), 'resume-transport-empty-acl')
        flags = acl.get('snapshotFlags'); fs = self.host.filesystem(entry['fd'])
        need(type(flags) is int and 0 <= flags < 1 << 32 and flags == getattr(info, 'st_flags', None)
             and fs['typeName'] == 'apfs' and fs['flags'] & 0x1000
             and not fs['flags'] & (0x20 | 0x200000 | 0x400000), 'resume-transport-local-apfs')
        self.outer.check_one(entry)
        need(identity(os.fstat(entry['fd'])) == identity(info), 'resume-transport-facts-post')
        self.clock.check()
        return identity(info), flags, fs

    def transport_roster(self, entry):
        before = self.transport_facts(entry); rows = {}
        self.quota.reserve(1)  # Before acquiring the iterator's transient FD.
        original, primary = None, None
        try:
            original = os.scandir(entry['fd'])
            for item in original:
                self.clock.check()
                need(len(rows) < 350 and item.name not in rows, 'resume-transport-roster-bound')
                info = os.stat(item.name, dir_fd=entry['fd'], follow_symlinks=False)
                rows[item.name] = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
        except BaseException as error:
            primary = error
            raise
        finally:
            if original is not None:
                consumed, original = original, None
                try:
                    consumed.close()
                except BaseException:
                    self.outer.errors.append('resume-transport-iterator-close-unknown')
                    if primary is None: raise
                    BaseException.add_note(primary, 'resume-transport-iterator-close-unknown')
        for name, expected in rows.items():
            self.clock.check()
            info = os.stat(name, dir_fd=entry['fd'], follow_symlinks=False)
            need((info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)) == expected, 'resume-transport-roster-post')
        need(self.transport_facts(entry) == before, 'resume-transport-scan-parent-post')
        return rows, before

    def acquire_fixed(self):
        self.point(); self.quota.reserve(3)
        request = {'row': ORIGIN, 'role': 'carrier', 'target': TARGETS[0], 'work': str(self.work),
                   'workIdentity': list(self.parent['identity']), 'caPath': self.ca_path, 'caSha256': self.ca_sha,
                   'endpoint': min(self.clock.work, self.clock.check() + 120_000_000_000)}
        env = dict(self.environment, MRK_P0_REQUEST=canonical(request).decode('ascii'), MRK_P0_READ_TOKEN=self.token)
        bootstrap = '__name__="__main__"; __file__=' + repr(str(self.root / 'desktop/tools/macos_fixed_carrier_resume.py')) + ';\n' + self.script.decode('utf-8')
        need(len(bootstrap.encode()) <= SOURCE_LIMIT + 1024, 'resume-fixed-child-source')
        result = self.command('acquire-carrier', [self.python, '-I', '-S', '-B', '-c', bootstrap, 'acquire'], 120, env=env)
        need(result.returncode == 0 and result.stderr == b'' and decode(result.stdout) == {'schemaVersion': 1, 'role': 'carrier',
             'target': TARGETS[0], 'bytes': ORIGIN['artifactBytes'], 'sha256': ORIGIN['artifactSha256'],
             'closedMetadataMatched': True, 'originalClosesKnown': True}, 'resume-original-acquisition')
        entry, body = self.quota.call(self.outer, 'file', self.work / 'arm64-carrier.zip', ORIGIN['artifactBytes'], modes=(0o600,))
        self.private['arm64-carrier.zip'] = entry['identity']
        values = fixed_members(body, self.clock)
        need(self.outer.read(entry) == body, 'resume-acquisition-original-post')
        return values

    def install_image(self, image, preview):
        self.publish_image(self.work / 'arm64.dmg', image)
        image_entry, original = self.quota.call(self.outer, 'file', self.work / 'arm64.dmg', len(image), modes=(0o444,))
        need(original == image, 'resume-image-copy-original')
        del original
        self.private['arm64.dmg'] = image_entry['identity']
        mount = transport_path_data(self.run_id, self.run_attempt)
        volumes = self.quota.call(self.outer, 'directory', Path('/Volumes'))
        slash = self.outer.directories[Path('/')]
        slash_facts = self.transport_facts(slash)
        roster, volumes_facts = self.transport_roster(volumes)
        need(mount.name not in roster, 'resume-transport-collision')
        attached, mounted, primary, detached, device = False, None, None, False, None
        member, mounted_roster = None, None
        self.installer_entered = self.installer_zero = self.readback_known = False
        try:
            STATE['phase'] = 'attach'
            call = self.command('attach', ['/usr/bin/hdiutil', 'attach', '-readonly', '-nobrowse', '-owners', 'on',
                '-mountpoint', str(mount), '-plist', str(self.work / 'arm64.dmg')], 60)
            need(call.returncode == 0, 'resume-original-attach')
            device = self.stager.distribution_mount_data(call.stdout, call.stderr, call.returncode, mount)
            attached = True
            mounted = self.fresh_book(transport=True); directory = self.quota.call(mounted, 'directory', mount)
            member = (directory['identity'][0], directory['identity'][1], stat.S_IFDIR)
            mounted_roster, current = self.transport_roster(volumes)
            transport_transition_data(roster, mounted_roster, volumes_facts, current, mount.name, member, present=True)
            volumes_facts = current
            def post():
                self.point(); mounted.check()
                held = os.fstat(directory['fd']); facts = self.host.filesystem(directory['fd'])
                mount_data(held, os.fstat(volumes['fd']), facts, os.fstatvfs(directory['fd']).f_flag, mount, device)
                need(not facts['flags'] & 0x400000, 'resume-transport-no-automount')
                need(self.transport_facts(slash) == slash_facts and self.transport_facts(volumes) == volumes_facts,
                     'resume-transport-retained-parents')
                need(identity(os.stat(mount.name, dir_fd=volumes['fd'], follow_symlinks=False)) == identity(held)
                     and set(os.listdir(directory['fd'])) == {'Install.pkg', 'producer.json', 'producer.sig'}, 'resume-mounted-original-roster')
                need(self.outer.read(image_entry) == image, 'resume-image-retained-post')
                return facts
            facts = post(); originals = {}
            for key in ('package', 'descriptor', 'signature'):
                selected = ORIGIN[key]; info = os.stat(selected['name'], dir_fd=directory['fd'], follow_symlinks=False)
                need(info.st_uid in (0, os.getuid()) and info.st_gid in (0, os.getgid()), 'resume-mounted-owner')
                entry, data = self.quota.call(mounted, 'file', mount / selected['name'], selected['bytes'], uid=info.st_uid, modes=(0o444,))
                need((len(data), sha(data)) == (selected['bytes'], selected['sha256']), 'resume-mounted-content-pin')
                originals[selected['name']] = (data, 0o444)
            row = dict(ORIGIN, members=[{'name': 'MobileReleaseKit.dmg', 'bytes': len(image), 'sha256': sha(image)},
                 {'name': 'PREVIEW.json', 'bytes': self.preview_bytes, 'sha256': self.preview_sha}],
                 inventorySha256=preview['installerInventorySha256'], runtimeManifestSha256=preview['runtimeManifestSha256'],
                 signingIdentity=self.signing_identity)
            result, inventory = mounted_data(originals, row, TARGETS[0], self.stager,
                allocation_budget=self.allocation_budget)
            need(post() == facts, 'resume-mounted-parser-post')
            STATE['phase'] = 'producer-signature'
            key = self.command('producer-key', ['/usr/bin/openssl', 'x509', '-inform', 'DER', '-in',
                str(self.root / 'desktop/packaging/macos-install-producer-certificates/leaf.der'), '-pubkey', '-noout'], 15)
            need(key.returncode == 0 and key.stderr == b'' and 0 < len(key.stdout) <= 16384
                 and key.stdout.startswith(b'-----BEGIN PUBLIC KEY-----\n') and key.stdout.endswith(b'-----END PUBLIC KEY-----\n'), 'resume-original-public-key')
            self.publish_owned(self.work / 'producer-key.pem', key.stdout)
            message = producer_message_data(originals['producer.json'][0])
            message_path = self.work / 'producer-message.bin'
            self.publish_owned(message_path, message)
            message_entry, message_readback = self.quota.call(
                self.outer, 'file', message_path, len(message), modes=(0o444,))
            need(message_readback == message, 'resume-producer-message-readback')
            verified = self.command('producer-signature', ['/usr/bin/openssl', 'dgst', '-sha256', '-verify', str(self.work / 'producer-key.pem'),
                '-signature', str(mount / 'producer.sig'), str(message_path)], 15)
            need(verified.returncode == 0, 'resume-native-producer-signature')
            need(verified.stdout == b'Verified OK\n', 'resume-native-producer-signature')
            need(verified.stderr == b'', 'resume-native-producer-signature')
            need(self.outer.read(message_entry) == message, 'resume-producer-message-post')
            need(post() == facts, 'resume-producer-mounted-signature-post')
            readback = original_release_readback_data(result, inventory, target=TARGETS[0])
            input_parent = self.fresh_directory(self.parent, 'input')
            self.publish_owned(input_parent['path'] / self.stager.INSTALLATION_INVENTORY_NAME, inventory)
            args = argparse.Namespace(target=TARGETS[0], fixture=False, input=self.work / 'input', expected_source=ORIGIN['source'],
                expected_inventory=row['inventorySha256'], expected_manifest=row['runtimeManifestSha256'],
                expected_package=ORIGIN['package']['sha256'], request_id=None,
                producer_descriptor=mount / 'producer.json', producer_signature=mount / 'producer.sig',
                installer_status=self.work / 'installer-output.status', package=mount / 'Install.pkg')
            self.point(); before_census = self.stager.same_package_result_census()
            need(before_census == {}, 'resume-fresh-installer-result-census')
            need(post() == facts, 'resume-installer-input-post')
            STATE['phase'] = 'installer'
            need(self.clock.seconds(123) == 123, 'resume-installer-original-clock-reserve')
            self.installer_entered = True
            original = self.command('installer', ['/usr/bin/sudo', '-n', '--', '/usr/sbin/installer', '-pkg', str(args.package),
                '-target', '/', '-dumplog', '-verboseR'], 123)
            self.installer_zero = original.returncode == 0
            if not self.installer_zero:
                STATE['installerObservation'] = installer_observation_data(original.returncode, original.stdout, original.stderr)
            need(self.installer_zero, 'resume-original-installer-zero')
            self.publish_owned(self.work / 'installer-output.status', b'0\n', 0o600)
            STATE['phase'] = 'readback'
            self.point(); need(post() == facts, 'resume-post-installer-mounted-inputs')
            after_census = self.stager.same_package_result_census()
            request_id = fresh_installer_request_data(before_census, after_census)
            args.request_id = request_id
            observed = self.stager.observation_command(args, original_release_readback=readback)
            self.point(); need(self.stager.same_package_result_census() == after_census, 'resume-installer-result-census-post')
            need(set(after_census) == {request_id} and observed['requestId'] == request_id
                 and observed['originalInstallerReturnedZero'] is True and observed['originalWriterJoined'] is True
                 and observed['sourceCommit'] == ORIGIN['source'] and observed['completedPackageSha256'] == ORIGIN['package']['sha256']
                 and observed['inventorySha256'] == row['inventorySha256'] and observed['runtimeManifestSha256'] == row['runtimeManifestSha256'],
                 'resume-current-installer-result-join')
            self.readback_known = True
            for role, path, identifier in (('entry-signature', self.stager.INSTALL_ROOT / self.stager.APP_NAME, self.stager.ENTRY_BUNDLE_ID),
                 ('payload-signature', self.stager.INSTALL_ROOT / self.stager.APP_NAME / 'Contents/Helpers/MobileReleaseKitPayload.app', self.stager.BUNDLE_ID)):
                requirement = ('=identifier "' + identifier + '" and anchor apple generic'
                    ' and certificate 1[field.1.2.840.113635.100.6.2.6] exists'
                    ' and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
                    ' and certificate leaf[subject.OU] = "' + self.signing_identity['teamIdentifier'] + '"'
                    ' and certificate leaf = H"' + self.signing_identity['leafCertificateSha1'] + '"')
                signature = self.command(role, ['/usr/bin/codesign', '--verify', '--strict', '--test-requirement', requirement, str(path)], 30)
                need(signature.returncode == 0 and signature.stdout == b'' and signature.stderr == b'', 'resume-installed-signature')
            need(post() == facts, 'resume-pre-detach-originals')
            self.installation = observed
        except BaseException as error:
            primary = error
            if STATE['firstFailurePhase'] is None:
                STATE['firstFailurePhase'] = STATE['phase']
            raise
        finally:
            # Actual failed Installer/readback cannot be turned into known mount
            # cleanup. Existing package-install semantics retain unknown state.
            if attached and (not self.installer_entered or self.installer_zero and self.readback_known):
                STATE['phase'] = 'detach-finality'; self.clock.finality = True
                closed = mounted is None or mounted.finish()
                if closed:
                    try:
                        self.point(); call = self.command('detach', ['/usr/bin/hdiutil', 'detach', device], 30)
                        need(call.returncode == 0, 'resume-original-detach')
                        need(member is not None and mounted_roster is not None, 'resume-transport-mounted-state-unobserved')
                        after, current = self.transport_roster(volumes)
                        transport_transition_data(mounted_roster, after, volumes_facts, current, mount.name, member, present=False)
                        need(after == roster and self.transport_facts(slash) == slash_facts, 'resume-transport-detach-post')
                        detached = True
                    except BaseException:
                        if primary is None: raise
                        BaseException.add_note(primary, 'resume-detach-finality-failed')
                elif primary is None: raise Refused('resume-mounted-close-unknown')
                else: BaseException.add_note(primary, 'resume-mounted-close-unknown')
                self.clock.finality = False
            self.mount_detached = detached
            if primary is None: need(attached and detached, 'resume-image-finality')

    def retire(self):
        self.point(); self.outer.check()
        # Only our fixed outputs, never installed root, source, vault or user data.
        for book in self.quota.books:
            if isinstance(book, FixedSudoOriginals):
                continue  # Keep all four originals until the global final close.
            for entry in book.entries:
                if entry['kind'] != 'directory': book.close(entry)
        need(all(not book.errors for book in self.quota.books), 'resume-private-original-close')
        for spelling, before in self.private.items():
            path = self.work / spelling
            parent = self.outer.directories[path.parent]
            need(identity(os.stat(path.name, dir_fd=parent['fd'], follow_symlinks=False)) == before, 'resume-retirement-original')
            os.unlink(path.name, dir_fd=parent['fd'])
        input_parent = self.outer.directories[self.work / 'input']
        need(os.listdir(input_parent['fd']) == [], 'resume-input-retirement-roster')
        self.outer.close(input_parent); need(input_parent['closed'], 'resume-input-directory-close')
        os.rmdir('input', dir_fd=self.parent['fd'])
        self.outer.check(); need(os.listdir(self.parent['fd']) == [], 'resume-task-retirement-roster')
        STATE['privateOutputsRetired'] = True


def admit_pinned_tls_roots(session):
    # The existing SOURCE book retains every ancestor and the original leaf.
    # No shared default store, configuration lookup or unchecked root fallback.
    body = session.source(TLS_CA_PATH, TLS_CA_BYTES, TLS_CA_SHA256)
    need(len(body) == TLS_CA_BYTES, 'resume-pinned-ca-size')
    session.ca_path = str(session.root / TLS_CA_PATH)
    session.ca_sha = TLS_CA_SHA256
    return body


# Detached ordinary-family draft for integration into the existing adapter.
# Not an executor, not imported, reviewed or exercised; no publication authority.
NORMAL_SCOPE = 'fixed-ce644-arm-carrier-normal-local-batch-v1'
NORMAL_BATCH_ENV = 'TEST_RUNNER_MRK_NORMAL_UI_FIXED_NORMAL_BATCH'
NORMAL_FAMILIES = {
    'launch-project': (('test.xcresult', 'test', 'summary', 1, 345),
                       ('project-test.xcresult', 'project-test', 'project-summary', 2, 885)),
    'doctor-saved-checks': (('diagnostics-test.xcresult', 'diagnostics-test', 'diagnostics-summary', 1, 585),
                            ('saved-checks-test.xcresult', 'saved-checks-test', 'saved-checks-summary', 2, 885)),
    'local-github-evidence': (('workflow-refusal-test.xcresult', 'workflow-refusal-test', 'workflow-refusal-summary', 1, 585),
                              ('release-evidence-test.xcresult', 'release-evidence-test', 'release-evidence-summary', 1, 585)),
    'persistence': (('persistence-test.xcresult', 'persistence-test', 'persistence-summary', 1, 585),),
    'saved-version-recovery': (('saved-version-recovery-test.xcresult', 'saved-version-recovery-test', 'saved-version-recovery-summary', 1, 585),),
}


def normal_batch_data(env):
    """Finite route only; native context/owner admission remains mandatory."""
    batch = env.get(NORMAL_BATCH_ENV)
    need(type(batch) is str and batch in NORMAL_FAMILIES, 'resume-normal-fixed-batch')
    return batch


def normal_installer_projection_data(install, batch, source, run_id, attempt):
    need(type(batch) is str and batch in NORMAL_FAMILIES, 'resume-normal-installer-batch')
    need(type(install) is dict and install.get('scope') == NORMAL_SCOPE and install.get('normalBatch') == batch
         and install.get('producerSource') == ORIGIN['source'] and install.get('producerTree') == ORIGIN['tree']
         and (install.get('producerRunId'),install.get('producerRunAttempt'),install.get('producerJobId'))
              == (ORIGIN['runId'],ORIGIN['runAttempt'],ORIGIN['jobId'])
         and install.get('artifactId') == ORIGIN['artifactId'] and install.get('artifactSha256') == ORIGIN['artifactSha256']
         and (install.get('consumerSource'),install.get('consumerRunId'),install.get('consumerRunAttempt'))
              == (source,run_id,attempt) and install.get('target') == TARGETS[0]
         and all(install.get(k) is True for k in ('originalInstallerReturnedZero','sameRequestReadback','originalMountDetached',
                 'originalClosesKnown','workloadsKnownSettled','privateOutputsRetired'))
         and all(install.get(k) is False for k in ('productReady','p0Qualified','intelQualified'))
         and install.get('receiptAuthority') == 'same-consumer-owned-installer-and-readback-not-old-status',
         'resume-normal-installer-original')
    if batch == 'saved-version-recovery':
        origin = install.get('savedVersionRuntimeOrigin')
        need(type(origin) is dict and set(origin) == {'scope','sourceCommit','release','runtimeManifestSha256','installationInventorySha256'}
             and origin['scope'] == 'fixed-original-release-saved-version-runtime-v1'
             and origin['sourceCommit'] == ORIGIN['source'] and origin['release'] == ORIGIN['release']
             and all(type(origin[k]) is str and re.fullmatch(r'[0-9a-f]{64}',origin[k]) for k in ('runtimeManifestSha256','installationInventorySha256')),
             'resume-normal-saved-runtime-origin')
    else:
        need('savedVersionRuntimeOrigin' not in install, 'resume-normal-no-foreign-runtime-purpose')


def normal_original_projection_data(row, batch, source, phase, seconds, bundle):
    """Use the existing original command/codesign/source/clock receipt contract."""
    need(type(row) is dict and row.get('sourceCommit') == source and row.get('target') == TARGETS[0]
         and row.get('fixedCarrierResumeScope') == NORMAL_SCOPE and row.get('fixedNormalBatch') == batch
         and row.get('applicationSourceCommit') == ORIGIN['source']
         and all(row.get(k) is False for k in ('currentProductQualified','p0Qualified','intelQualified'))
         and row.get('sourcePrePostMatched') is True and row.get('originalCommandReturned') is True
         and row.get('normalPhase' if phase == 'test' else 'phase') == phase and row.get('resultBundle') == bundle
         and type(row.get('originalTestReturncode' if phase == 'test' else 'originalReturncode')) is int
         and row['originalTestReturncode' if phase == 'test' else 'originalReturncode'] == 0
         and row.get('receiptPolicy') == 'exclusive0600-readback-consuming-close', 'resume-normal-original')
    roster = row.get('sourceRosterSha256')
    need(type(roster) is str and re.fullmatch(r'[0-9a-f]{64}',roster), 'resume-normal-source-roster')
    clock = row.get('phaseClock')
    need(type(clock) is dict and clock.get('postCloseDeadlineRequired') is True
         and all(type(clock.get(k)) is str and re.fullmatch(r'0|[1-9][0-9]{0,19}',clock[k])
                 for k in ('startNs','deadlineNs','beforePublicationNs')), 'resume-normal-phase-clock')
    start,end,before = (int(clock[k]) for k in ('startNs','deadlineNs','beforePublicationNs'))
    need(end-start == seconds*1_000_000_000 and start <= before < end, 'resume-normal-phase-clock')
    commands = row.get('commands')
    source_role = ('normal-ui-source-roster',15,1048576)
    roles = ([source_role,*[('normal-toolchain-'+k,15,4096) for k in ('xcode','sdkPath','sdkVersion','sdkBuild')],
              ('normal-ui-build',240,1048576),source_role] if phase == 'build' else
             [source_role,('verify-generated-runner',30,1048576),('generated-runner-entitlements',30,1048576),
              ('one-admitted-ui-test',{345:180,585:420,885:720}[seconds],1048576),source_role] if phase == 'test' else
             [source_role,('normal-ui-summary',30,262144),source_role])
    if phase == 'test' and batch == 'saved-version-recovery':
        roles[1:1] = [('saved-version-source-roster',15,65536),('saved-version-core-interrupt',20,65536)]
    keys = {'role','returncode','timeoutSeconds','roleCapSeconds','outputLimitBytes','argvSha256',
            'stdoutBytes','stdoutSha256','stderrBytes','stderrSha256'}
    need(type(commands) is list and len(commands) == len(roles), 'resume-normal-command-roster')
    for command,(role,cap,limit) in zip(commands,roles):
        need(type(command) is dict and set(command) == keys and command['role'] == role
             and type(command['returncode']) is int and command['returncode'] == (86 if role == 'saved-version-core-interrupt' else 0)
             and all(type(command[k]) is int for k in ('timeoutSeconds','roleCapSeconds','outputLimitBytes','stdoutBytes','stderrBytes'))
             and 1 <= command['timeoutSeconds'] <= command['roleCapSeconds'] == cap
             and command['outputLimitBytes'] == limit and 0 <= command['stdoutBytes'] <= limit
             and 0 <= command['stderrBytes'] <= limit-command['stdoutBytes']
             and all(type(command[k]) is str and re.fullmatch(r'[0-9a-f]{64}',command[k])
                     for k in ('argvSha256','stdoutSha256','stderrSha256')), 'resume-normal-command-finality')
    if phase == 'test' and batch == 'saved-version-recovery':
        need(commands[1]['stderrBytes'] == commands[2]['stderrBytes'] == 0, 'resume-normal-saved-prefix-stderr')
    need(commands[0]['stdoutSha256'] == commands[-1]['stdoutSha256']
         and commands[0]['stdoutBytes'] == commands[-1]['stdoutBytes'], 'resume-normal-original-source-query')
    return roster


def normal_family_projection_data(install, build, test, summary, summary_body, batch, bundle, source, run_id, attempt):
    """A family's real pass can be retained independently of its sibling's failure."""
    normal_installer_projection_data(install,batch,source,run_id,attempt)
    choices = [row for row in NORMAL_FAMILIES[batch] if row[0] == bundle]
    need(len(choices) == 1, 'resume-normal-family')
    _,test_stem,summary_stem,count,seconds = choices[0]
    rosters = [normal_original_projection_data(row,batch,source,phase,budget,result)
               for row,phase,budget,result in ((build,'build',450,None),(test,'test',seconds,bundle),(summary,'summary',90,bundle))]
    need(rosters[0] == rosters[1] == rosters[2] and test.get('originalClosesCompleted') is True
         and test.get('originalProductsPrePostMatched') is True and test.get('strictCodesignOriginalZero') is True
         and test.get('reSignedOrRepaired') is False, 'resume-normal-generated-products-finality')
    expected = {'totalTestCount':count,'passedTests':count,'failedTests':0,'skippedTests':0,'expectedFailures':0}
    need(type(summary_body) is bytes and 0 < len(summary_body) <= 262144, 'resume-normal-summary-body')
    counts = decode(summary_body, allow_finite_floats=True)
    need(type(counts) is dict and all(type(counts.get(k)) is int and counts[k] == v for k,v in expected.items()),
         'resume-normal-counts')
    need(summary['commands'][1]['stdoutBytes'] == len(summary_body)
         and summary['commands'][1]['stdoutSha256'] == sha(summary_body), 'resume-normal-original-summary-binding')
    markers = {'project-test.xcresult': ('projectFieldAndEditMarkersObserved','androidToolSourceBrowseMarkerObserved'),
               'workflow-refusal-test.xcresult': ('managedWorkflowRefusalMarkerObserved',),
               'release-evidence-test.xcresult': ('savedReleaseEvidenceMarkerObserved',)}
    need(all(test.get(k) is True for k in markers.get(bundle,())), 'resume-normal-existing-ui-markers')
    if batch == 'saved-version-recovery':
        saved = test.get('savedVersionRecovery'); origin = install['savedVersionRuntimeOrigin']
        need(type(saved) is dict and type(saved.get('originalRuntimeWitness')) is dict
             and saved['originalRuntimeWitness'] == {**origin,'coreVersion':'0.3.0','sourceInputsSha256':'10d3f2cf13155335444c8376a346d89581c03a43f0ae642e67401e379745dca2','runtimeOriginalsMatched':True}
             and saved.get('producerReturncode') == 86 and type(saved.get('producerReturncode')) is int
             and saved.get('publicOriginalCount') == 13 and saved.get('readyJournalFileCount') == 6
             and all(saved.get(k) is True for k in ('originalFixtureRestored','unrelatedOriginalsUnchanged','readyJournalRemoved','sourcePrePostMatched','uiOriginalMarkersObserved','originalClosesCompleted'))
             and saved.get('interruptedGuiSaveObserved') is False and saved.get('currentRuntimeQualified') is False
             and saved['originalRuntimeWitness'].get('runtimeOriginalsMatched') is True
             and saved.get('runtimeManifestSha256') == origin['runtimeManifestSha256']
             and saved.get('sourceInputsSha256') == saved['originalRuntimeWitness']['sourceInputsSha256']
             and saved.get('producerFramesSha256') == test['commands'][2]['stdoutSha256']
             and saved.get('originalRuntimeReceiptSha256') == sha(canonical(install) + b'\n')
             and 'runtimeResultSha256' not in saved, 'resume-normal-saved-genuine-recovery')
    return {'schemaVersion':1,'scope':NORMAL_SCOPE,'normalBatch':batch,'family':bundle,
            'producerSource':ORIGIN['source'],'producerTree':ORIGIN['tree'],
            'carrierArtifactId':ORIGIN['artifactId'],'carrierArtifactSha256':ORIGIN['artifactSha256'],
            'harnessSource':source,'consumerRunId':run_id,'consumerRunAttempt':attempt,'target':TARGETS[0],
            'freshInstallerReadback':'passed','currentHarnessBuild':'passed','familyResult':'passed',
            'sourceRosterSha256':rosters[0],'testCounts':expected,'rawTextExported':False,
            'currentProductQualified':False,'p0Qualified':False,'intelQualified':False,'productReady':False}


# Detached addition: actual family originals, never a previous job's live state.
def normal_projection_context():
    env = os.environ
    need(env.get('GITHUB_REPOSITORY') == REPOSITORY and env.get('GITHUB_REF') == ENROLLMENT_REF
         and env.get('GITHUB_SHA') == env.get('GITHUB_WORKFLOW_SHA') and env.get('GITHUB_SHA') != ORIGIN['source']
         and re.fullmatch(r'[0-9a-f]{40}',env.get('GITHUB_SHA',''))
         and env.get('GITHUB_WORKFLOW_REF') == REPOSITORY+'/'+RESUME_WORKFLOW+'@'+ENROLLMENT_REF,
         'resume-normal-projection-context')
    scope,batch = resume_selection_data(env)
    need(scope == NORMAL_SCOPE, 'resume-normal-projection-scope')
    root = Path(env['MRK_MACOS_WORK'])/'normal-ui'
    need(re.fullmatch(r'/Users/runner/work/_temp/mrk-macos-installed\.[A-Za-z0-9]{8}/normal-ui',str(root)),
         'resume-normal-projection-work')
    return env,batch,root


def normal_project_main(bundle):
    env,batch,root = normal_projection_context()
    choices = [row for row in NORMAL_FAMILIES[batch] if row[0] == bundle]
    need(type(bundle) is str and len(choices) == 1, 'resume-normal-family-route')
    _,test_stem,summary_stem,_,_ = choices[0]
    started = time.monotonic_ns(); originals = []; primary = None
    def read(name,cap):
        need(time.monotonic_ns() < started+10_000_000_000, 'resume-normal-projection-clock')
        path = root/name
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        originals.append((fd,path,None))
        before = identity(os.fstat(fd)); originals[-1] = (fd,path,before)
        need(stat.S_ISREG(before[2]) and stat.S_IMODE(before[2]) == 0o600
             and before[3:6] == (os.getuid(),os.getgid(),1) and 0 < before[6] <= cap
             and identity(os.stat(path,follow_symlinks=False)) == before, 'resume-normal-projection-file')
        body = os.pread(fd,before[6]+1,0)
        need(len(body) == before[6] and not os.pread(fd,1,before[6])
             and identity(os.fstat(fd)) == before, 'resume-normal-projection-read-post')
        return body
    try:
        for name in ('build.status',test_stem+'.status',summary_stem+'.status'):
            need(read(name,16) == b'0\n', 'resume-normal-caller-zero')
        rows = [decode(read(name,32768)) for name in ('fixed-carrier-install.json','build.command-admission.json',
                 test_stem+'.runner-admission.json',summary_stem+'.command-admission.json')]
        summary_body = read(summary_stem+'.json',262144)
        result = normal_family_projection_data(*rows,summary_body,batch,bundle,
                    env['GITHUB_SHA'],env['GITHUB_RUN_ID'],env['GITHUB_RUN_ATTEMPT'])
        for fd,path,before in originals:
            need(identity(os.fstat(fd)) == before == identity(os.stat(path,follow_symlinks=False)),
                 'resume-normal-projection-terminal-post')
    except BaseException as error:
        primary = error; raise
    finally:
        failures = []
        for fd,path,before in originals:
            try: os.close(fd)
            except BaseException: failures.append(1)
        if failures:
            if primary is None: raise Refused('resume-normal-projection-close')
            BaseException.add_note(primary,'resume-normal-projection-close')
    need(time.monotonic_ns() < started+10_000_000_000, 'resume-normal-projection-final-clock')
    return result


def normal_batch_project_main():
    env,batch,root = normal_projection_context()
    started = time.monotonic_ns(); originals = []; primary = None; families = []
    try:
        for bundle,test_stem,_,_,_ in NORMAL_FAMILIES[batch]:
            expected = normal_project_main(bundle)
            path = root/('fixed-normal-'+test_stem+'.json')
            fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
            originals.append((fd,path,None)); before = identity(os.fstat(fd)); originals[-1] = (fd,path,before)
            need(stat.S_ISREG(before[2]) and stat.S_IMODE(before[2]) == 0o600
                 and before[3:6] == (os.getuid(),os.getgid(),1) and 0 < before[6] <= 32768
                 and identity(os.stat(path,follow_symlinks=False)) == before, 'resume-normal-family-publication-original')
            body = os.pread(fd,before[6]+1,0)
            need(len(body) == before[6] and not os.pread(fd,1,before[6]) and body == canonical(expected)+b'\n'
                 and identity(os.fstat(fd)) == before, 'resume-normal-family-publication-readback')
            families.append({'family':bundle,'result':'passed','receiptSha256':sha(body),'testCounts':expected['testCounts']})
        for fd,path,before in originals:
            need(identity(os.fstat(fd)) == before == identity(os.stat(path,follow_symlinks=False)),
                 'resume-normal-batch-terminal-post')
    except BaseException as error:
        primary = error; raise
    finally:
        failures = []
        for fd,path,before in originals:
            try: os.close(fd)
            except BaseException: failures.append(1)
        if failures:
            if primary is None: raise Refused('resume-normal-batch-close')
            BaseException.add_note(primary,'resume-normal-batch-close')
    need(time.monotonic_ns() < started+30_000_000_000, 'resume-normal-batch-final-clock')
    return {'schemaVersion':1,'scope':NORMAL_SCOPE,'normalBatch':batch,'producerSource':ORIGIN['source'],
            'harnessSource':env['GITHUB_SHA'],'consumerRunId':env['GITHUB_RUN_ID'],
            'consumerRunAttempt':env['GITHUB_RUN_ATTEMPT'],'target':TARGETS[0],
            'families':families,'batchResult':'passed','rawTextExported':False,
            'currentProductQualified':False,'p0Qualified':False,'intelQualified':False,'productReady':False}

# Finite observation only. A failed/unknown row never authorizes another family
# or cleanup; already-closed family receipts remain independently interpretable.
INSTALLER_PHASES = ('entry','target-ok','relative-entry','absolute-entry','cwd-ok','pre-exec')
INSTALLER_REFUSALS = ('target','entry','cwd')
INSTALLER_ACL_ROLES = ('input-directory','input-inventory','system-root','system-library','system-support','other-protected-object')
INSTALLER_ACL_PHASES = ('filesec-allocation','fstatx-snapshot','snapshot-owner','snapshot-group','snapshot-mode','acl-presence','acl-conversion','acl-object','acl-validation','acl-first-entry','acl-entry-present','acl-free','ffi-output')


def installer_observation_projection_data(value):
    """Optional failure-only finite DATA; never raw captures or success authority."""
    keys = {'returncode','stdoutBytes','stderrBytes','postinstallPhases','postinstallRefusals','aclDiagnostics','completedParentRefusals','truncated','markerState'}
    if type(value) is not dict or set(value) != keys: return None
    if (type(value['returncode']) is not int or not -255 <= value['returncode'] <= 255 or value['returncode'] == 0
        or any(type(value[k]) is not int or value[k] < 0 for k in ('stdoutBytes','stderrBytes'))
        or value['stdoutBytes'] + value['stderrBytes'] > 256*1024 or type(value['truncated']) is not bool): return None
    for key, choices in (('postinstallPhases',INSTALLER_PHASES),('postinstallRefusals',INSTALLER_REFUSALS)):
        rows = value[key]
        if type(rows) is not list or len(rows) > len(choices) or any(type(v) is not str or v not in choices for v in rows): return None
        if rows != [v for v in choices if v in rows]: return None
    aclkeys = {'role','phase','result','call','errno','freeCall','freeErrno'}
    parentkeys = {'exit','originals','native','timely','unknown'}
    for key, fields, cap in (('aclDiagnostics',aclkeys,8),('completedParentRefusals',parentkeys,4)):
        rows = value[key]
        if type(rows) is not list or len(rows) > cap: return None
        for row in rows:
            if type(row) is not dict or set(row) != fields: return None
            if key == 'aclDiagnostics':
                if (type(row['role']) is not str or row['role'] not in INSTALLER_ACL_ROLES
                    or type(row['phase']) is not str or row['phase'] not in INSTALLER_ACL_PHASES
                    or any(type(row[k]) is not int or not -9999999999 <= row[k] <= 9999999999 for k in fields-{'role','phase'})): return None
            elif (type(row['exit']) is not int or row['exit'] not in (1,20)
                  or any(type(row[k]) is not bool for k in fields-{'exit'})): return None
    observed = any(value[k] for k in ('postinstallPhases','postinstallRefusals','aclDiagnostics','completedParentRefusals'))
    if value['markerState'] != ('observed' if observed else 'absent'): return None
    return {**value, **{k:[dict(v) if type(v) is dict else v for v in value[k]] for k in ('postinstallPhases','postinstallRefusals','aclDiagnostics','completedParentRefusals')}}


def installer_observation_data(code, stdout, stderr):
    """Classify only already-owned captures; failed diagnostics stay unavailable."""
    try:
        if (type(code) is not int or not -255 <= code <= 255 or code == 0
            or type(stdout) is not bytes or type(stderr) is not bytes or len(stdout)+len(stderr) > 256*1024): return None
        value = dict(returncode=code,stdoutBytes=len(stdout),stderrBytes=len(stderr),postinstallPhases=[],postinstallRefusals=[],aclDiagnostics=[],completedParentRefusals=[],truncated=False,markerState='absent')
        patterns = (
            ('postinstallPhases',re.compile(rb'(?<![A-Za-z0-9_])MRK_MACOS_POSTINSTALL_PHASE=(' + b'|'.join(v.encode() for v in INSTALLER_PHASES) + rb')(?![A-Za-z0-9_-])'),6),
            ('postinstallRefusals',re.compile(rb'(?<![A-Za-z0-9_])MRK_MACOS_POSTINSTALL_REFUSED=(' + b'|'.join(v.encode() for v in INSTALLER_REFUSALS) + rb')(?![A-Za-z0-9_-])'),3),
            ('aclDiagnostics',re.compile(rb'(?<![A-Za-z0-9_])MRK_MACOS_INSTALL_ACL_DIAGNOSTIC=role=(' + b'|'.join(v.encode() for v in INSTALLER_ACL_ROLES) + rb');phase=(' + b'|'.join(v.encode() for v in INSTALLER_ACL_PHASES) + rb');result=(-?[0-9]{1,10});call=(-?[0-9]{1,10});errno=(-?[0-9]{1,10});freeCall=(-?[0-9]{1,10});freeErrno=(-?[0-9]{1,10})(?=\r?\n$)'),8),
            ('completedParentRefusals',re.compile(rb'(?<![A-Za-z0-9_])MRK_MACOS_INSTALL_COMPLETED_REFUSED=reasonSha256=[0-9a-f]{64};exit=(1|20);originals=([01]);native=([01]);timely=([01]);unknown=([01])(?=\r?\n$)'),4))
        for body in (stdout,stderr):
            for line in body.splitlines(keepends=True):
                if len(line) > 16384:
                    value['truncated'] = True; continue
                for key, pattern, cap in patterns:
                    for match in pattern.finditer(line):
                        parts = match.groups()
                        row = (dict(zip(('role','phase','result','call','errno','freeCall','freeErrno'),[parts[0].decode('ascii'),parts[1].decode('ascii'),*[int(p) for p in parts[2:]]])) if key == 'aclDiagnostics' else
                               dict(zip(('exit','originals','native','timely','unknown'),[int(parts[0]),*[p == b'1' for p in parts[1:]]])) if key == 'completedParentRefusals' else parts[0].decode('ascii'))
                        if len(value[key]) == cap or row in value[key]: value['truncated'] = True
                        else: value[key].append(row)
        for key, choices in (('postinstallPhases',INSTALLER_PHASES),('postinstallRefusals',INSTALLER_REFUSALS)):
            value[key] = [v for v in choices if v in value[key]]
        if any(value[k] for k,_,_ in patterns): value['markerState'] = 'observed'
        return installer_observation_projection_data(value)
    except BaseException:
        return None  # No diagnostic error can replace the known failed Installer.


PROJECT_STAGES = tuple('launch fixture project-open android-source-jdk android-source-sdk android-source-gradle android-source-cancel android-source-reselect android-source-refused field-version field-project field-workspace field-metadata field-file-cancel field-directory-cancel field-review quit project-cancel config github text version images-cancel images readback-and-quit'.split())


def project_test_failure_data(v, status):
    """Optional fixed project observation, never raw text or release authority."""
    if (type(v) is not dict or type(status) is not int or not 1 <= status <= 255
        or type(v.get('schemaVersion')) is not int or v['schemaVersion'] != 1
        or v.get('scope') != 'normal-macos-ui-failure-diagnostic-only' or v.get('phase') != 'test'
        or v.get('selection') != 'project-test.xcresult' or type(v.get('originalReturncode')) is not int
        or v['originalReturncode'] != status or v.get('status') not in ('unavailable','classified','unclassified')
        or type(v.get('findingsTruncated')) is not bool): return None
    rows = v.get('sourceFailures'); progress = v.get('projectProgress')
    if type(rows) is not list or len(rows) > 4: return None
    for i,r in enumerate(rows):
        if (type(r) is not dict or set(r) != {'stream','source','method','line','column'} or r in rows[:i]
            or r['stream'] not in ('stdout','stderr') or r['source'] != 'NormalAppUITests.swift'
            or r['method'] not in ('testSyntheticProjectLocalEditsAndImages','testSyntheticProjectPathFields')
            or type(r['line']) is not int or not 1 <= r['line'] <= 65535
            or not (r['column'] is None or type(r['column']) is int and 1 <= r['column'] <= 4096)): return None
    if progress is not None:
        if type(progress) is not dict or set(progress) != {'state','firstFailed','lastObserved'}: return None
        state,first,last = (progress[k] for k in ('state','firstFailed','lastObserved'))
        if state == 'observed':
            if (first is not None and first not in PROJECT_STAGES or type(last) is not dict
                or set(last) != {'stage','result'} or last['stage'] not in PROJECT_STAGES
                or last['result'] not in ('started','passed','failed') or last['result'] == 'failed' and first is None): return None
        elif state not in ('absent','refused') or first is not None or last is not None: return None
    result = {**{k:v[k] for k in ('phase','selection','originalReturncode','status','findingsTruncated')},
            'sourceFailures':[dict(r) for r in rows],'projectProgress':None if progress is None else {**progress,
            'lastObserved':None if progress['lastObserved'] is None else dict(progress['lastObserved'])}}
    if 'projectNavigation' in v:
        nav = v['projectNavigation']; states = ('absent','ambiguous','disabled','obscured','ready')
        relations = ('non-string','exact','empty','trailing-slash','tmp-alias','tmp-alias-trailing-slash',
            'case-only','case-only-trailing-slash','tmp-alias-case-only','tmp-alias-case-only-trailing-slash',
            'prefix','extra-suffix','suffix','other')
        keys = {'method','phase','role','relation','unchangedFromBefore','elementState','fields','combos',
                'go','open','cancel','nonAtomic'}
        valid = (type(nav) is dict and set(nav) == {'state','observations'}
            and type(nav['observations']) is list and (nav['state'] in ('absent','refused')
            and not nav['observations'] or nav['state'] == 'observed' and 1 <= len(nav['observations']) <= 4))
        seen = set()
        if valid:
            for row in nav['observations']:
                if (type(row) is not dict or set(row) != keys
                    or row['method'] not in ('testSyntheticProjectPathFields','testSyntheticProjectLocalEditsAndImages')
                    or row['phase'] not in ('after-typing','after-return-timeout')
                    or row['role'] not in ('standalone-field','combo-child','combo') or row['relation'] not in relations
                    or type(row['unchangedFromBefore']) is not bool
                    or row['relation'] == 'non-string' and row['unchangedFromBefore']
                    or row['elementState'] not in ('absent','disabled','obscured','ready')
                    or any(type(row[k]) is not int or not 0 <= row[k] <= 2 for k in ('fields','combos'))
                    or any(row[k] not in states for k in ('go','open','cancel')) or row['nonAtomic'] is not True
                    or (row['method'],row['phase']) in seen):
                    valid = False; break
                seen.add((row['method'],row['phase']))
        result['projectNavigation'] = {'state':nav['state'],'observations':[dict(r) for r in nav['observations']]} if valid else {'state':'refused','observations':[]}
        if not valid: result['findingsTruncated'] = True
    return result


def normal_projection_failure_data(value, batch, statuses):
    if type(value) is not dict or set(value) != {'family','failureLocation'}: return None
    family = value['family']
    if type(family) is not str or family not in {r[0] for r in NORMAL_FAMILIES[batch]}: return None
    status = statuses[family]['result']
    if type(status) is not int or not 1 <= status <= 255: return None
    return {'family':family,'failureLocation':location_data(value['failureLocation'])}


def normal_failure_data(native,batch,statuses,passed,harness_status, *, projection_failure=None):
    need(type(batch) is str and batch in NORMAL_FAMILIES, 'resume-normal-diagnostic-batch')
    expected = {row[0] for row in NORMAL_FAMILIES[batch]}
    need(type(statuses) is dict and set(statuses) == expected and type(passed) is set and passed <= expected,
         'resume-normal-diagnostic-roster')
    rows = []
    for bundle,_,_,_,_ in NORMAL_FAMILIES[batch]:
        values = statuses[bundle]
        need(type(values) is dict and set(values) == {'test','summary','result'}
             and all(v is None or type(v) is int and 0 <= v <= 255 for v in values.values()),
             'resume-normal-diagnostic-status')
        need(bundle not in passed or all(type(v) is int and v == 0 for v in values.values()),
             'resume-normal-diagnostic-passed-status')
        state = ('passed' if bundle in passed else 'not-run' if all(v is None for v in values.values())
                 else 'failed' if any(type(v) is int and v != 0 for v in values.values()) else 'unknown')
        rows.append({'family':bundle,'state':state,'callerStatuses':dict(values)})
    need(harness_status is None or type(harness_status) is int and 0 <= harness_status <= 255,
         'resume-normal-diagnostic-harness')
    native_row = {'state':'unavailable','phase':None,'originalClosesKnown':None,'workloadsKnownSettled':None,
                  'privateOutputsRetired':None,'failureLocation':unavailable_location(),'resourceAdmission':None,'installerObservation':None}
    allowed = ('admission','initial-source','attach','producer-signature','installer','readback','detach-finality',
               'resource-admission','acquire-carrier','complete')
    if type(native) is dict and native.get('schemaVersion') == 1 and native.get('scope') == NORMAL_SCOPE and native.get('normalBatch') == batch and native.get('accepted') is False:
        phase = native.get('firstFailurePhase') or native.get('phase')
        if type(phase) is str and phase in allowed:
            native_row.update(state='observed-failure',phase=phase,failureLocation=location_data(native.get('failureLocation')))
            native_row['resourceAdmission'] = resource_projection_data(native.get('resourceAdmission'))
            if phase == 'installer': native_row['installerObservation'] = installer_observation_projection_data(native.get('installerObservation'))
            for key in ('originalClosesKnown','workloadsKnownSettled','privateOutputsRetired'):
                native_row[key] = native.get(key) if type(native.get(key)) is bool else None
    return {'schemaVersion':1,'scope':NORMAL_SCOPE,'normalBatch':batch,'families':rows,
            'projectionFailure':normal_projection_failure_data(projection_failure,batch,statuses),
            'harnessReturncode':harness_status,'native':native_row,'purpose':'finite-current-consumer-observation-only',
            'successInferred':False,'unknownStateNotConvertedToCleanup':True,'rawTextExported':False,
            'currentProductQualified':False,'p0Qualified':False,'intelQualified':False,'productReady':False}

# Observation must preserve source/close failure as unknown, never as success.
def normal_diagnostic_main():
    env,batch,root = normal_projection_context()
    started = time.monotonic_ns(); originals = []; primary = None
    def optional(name,cap):
        need(time.monotonic_ns() < started+30_000_000_000, 'resume-normal-diagnostic-clock')
        path = root/name
        try: fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        except FileNotFoundError: return None
        originals.append((fd,path,None)); before = identity(os.fstat(fd)); originals[-1] = (fd,path,before)
        need(stat.S_ISREG(before[2]) and stat.S_IMODE(before[2]) == 0o600
             and before[3:6] == (os.getuid(),os.getgid(),1) and 0 <= before[6] <= cap
             and identity(os.stat(path,follow_symlinks=False)) == before, 'resume-normal-diagnostic-file')
        body = os.pread(fd,before[6]+1,0)
        need(len(body) == before[6] and not os.pread(fd,1,before[6]) and identity(os.fstat(fd)) == before,
             'resume-normal-diagnostic-read-post')
        return body
    def status(name):
        body = optional(name,16)
        return int(body) if body is not None and re.fullmatch(rb'(0|[1-9][0-9]{0,2})\n',body) and int(body) <= 255 else None
    try:
        statuses = {}; passed = set(); ui = None; projection_failure = None; project_failure = None
        for bundle,test_stem,summary_stem,_,_ in NORMAL_FAMILIES[batch]:
            values = {'test':status(test_stem+'.status'),'summary':status(summary_stem+'.status'),
                      'result':status('fixed-normal-'+test_stem+'.status')}
            statuses[bundle] = values
            if projection_failure is None and type(values['result']) is int and values['result'] != 0:
                body = optional('fixed-normal-'+test_stem+'.json',4096)
                try: candidate = decode(body) if body else None
                except ValueError: candidate = None # Optional JSON only; original read/POST/close still fail closed.
                keys = {'schemaVersion','scope','normalBatch','accepted','phase','productReady','currentProductQualified','p0Qualified','intelQualified','failureLocation'}
                if (type(candidate) is dict and set(candidate) == keys and type(candidate['schemaVersion']) is int
                    and candidate['schemaVersion'] == 1 and candidate['scope'] == NORMAL_SCOPE
                    and candidate['normalBatch'] == batch and candidate['phase'] == 'projection'
                    and all(candidate[k] is False for k in ('accepted','productReady','currentProductQualified','p0Qualified','intelQualified'))):
                    projection_failure = {'family':bundle,'failureLocation':location_data(candidate['failureLocation'])}
            if all(type(v) is int and v == 0 for v in values.values()):
                try:
                    expected = normal_project_main(bundle)
                    body = optional('fixed-normal-'+test_stem+'.json',32768)
                    if body == canonical(expected)+b'\n': passed.add(bundle)
                except (Refused,OSError,ValueError,TypeError):
                    pass # Earlier unverifiable publication remains unknown.
            for stem in (test_stem,summary_stem):
                body = optional(stem+'.failure-diagnostics.json',4096)
                try: candidate = decode(body) if body else None
                except ValueError: candidate = None
                if stem == 'project-test': project_failure = project_test_failure_data(candidate,values['test'])
                if ui is None and type(candidate) is dict and candidate.get('scope') == 'normal-macos-ui-admission-diagnostic-only':
                    ui = candidate
        body = optional('build.failure-diagnostics.json',4096)
        candidate = decode(body) if body else None
        if ui is None and type(candidate) is dict and candidate.get('scope') == 'normal-macos-ui-admission-diagnostic-only':
            ui = candidate
        body = optional('fixed-carrier-install.json',16384)
        native = decode(body) if body else None
        result = normal_failure_data(native,batch,statuses,passed,status('build.status'), projection_failure=projection_failure)
        admission = finite_failure_data(None,{k:None for k in ('installer','harness','ios','summary','result')},ui)
        result.update(projectTestFailure=project_failure,admissionExceptionClass=admission['admissionExceptionClass'],
                      admissionStage=admission['admissionStage'],ownerFailure=admission['ownerFailure'],
                      producerSource=ORIGIN['source'],consumerSource=env['GITHUB_SHA'],
                      consumerRunId=env['GITHUB_RUN_ID'],consumerRunAttempt=env['GITHUB_RUN_ATTEMPT'])
        for fd,path,before in originals:
            need(identity(os.fstat(fd)) == before == identity(os.stat(path,follow_symlinks=False)),
                 'resume-normal-diagnostic-terminal-post')
    except BaseException as error:
        primary = error; raise
    finally:
        failures = []
        for fd,path,before in originals:
            try: os.close(fd)
            except BaseException: failures.append(1)
        if failures:
            if primary is None: raise Refused('resume-normal-diagnostic-close')
            BaseException.add_note(primary,'resume-normal-diagnostic-close')
    need(time.monotonic_ns() < started+30_000_000_000, 'resume-normal-diagnostic-final-clock')
    return result


def resume_selection_data(env):
    marker = env.get('TEST_RUNNER_MRK_NORMAL_UI_FIXED_CARRIER_RESUME')
    if env.get(NORMAL_BATCH_ENV) is None:
        need(marker in (None,SCOPE), 'resume-legacy-scope')
        return SCOPE,None
    need(marker == NORMAL_SCOPE, 'resume-normal-explicit-scope')
    return NORMAL_SCOPE,normal_batch_data(env)


def main():
    env = os.environ
    started = env.get('MRK_FIXED_RESUME_STARTED_NS', '')
    need(re.fullmatch(r'[1-9][0-9]{0,19}', started), 'resume-started-original')
    clock = Deadline(started=int(started))
    need(sys.version_info[:3] == (3, 14, 7) and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
         and sys.platform == 'darwin' and platform.machine() == 'arm64' and os.getuid() != 0 and os.getuid() == os.geteuid()
         and os.getgid() == os.getegid() and env.get('RUNNER_OS') == 'macOS' and env.get('RUNNER_ARCH') == 'ARM64'
         and env.get('RUNNER_ENVIRONMENT') == 'github-hosted' and env.get('GITHUB_EVENT_NAME') == 'push'
         and env.get('GITHUB_REPOSITORY') == REPOSITORY and env.get('GITHUB_REF') == ENROLLMENT_REF
         and env.get('GITHUB_WORKFLOW_REF') == REPOSITORY + '/' + RESUME_WORKFLOW + '@' + ENROLLMENT_REF
         and env.get('GITHUB_SHA') == env.get('GITHUB_WORKFLOW_SHA') and env.get('GITHUB_SHA') != ORIGIN['source']
         and re.fullmatch(r'[0-9a-f]{40}', env.get('GITHUB_SHA', ''))
         and all(re.fullmatch(r'[1-9][0-9]{0,19}', env.get(k, '')) for k in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')),
         'resume-current-harness-context')
    scope, normal_batch = resume_selection_data(env)
    root = Path(__file__).absolute().parents[2]
    need(str(root) == env.get('GITHUB_WORKSPACE') and str(root) == '/Users/runner/work/mobile-release-kit/mobile-release-kit'
         and env.get('RUNNER_TEMP') == '/Users/runner/work/_temp', 'resume-fixed-checkout')
    work = Path(env['MRK_MACOS_WORK']) / 'resume-carrier'
    need(re.fullmatch(r'/Users/runner/work/_temp/mrk-macos-installed\.[A-Za-z0-9]{8}/resume-carrier', str(work)), 'resume-fresh-work-route')
    quota = OriginalQuota(); quota.reserve(1)
    os.mkdir(work, 0o700)
    session, primary = None, None
    try:
        quota.reserve(1)
        session = Resume(root, work, clock, bootstrap_originals(root), quota=quota)
        # This body is passed to the isolated acquisition child. Keep its
        # command-size bound; module reads below have a different allowance.
        session.script = session.source('desktop/tools/macos_fixed_carrier_resume.py', SOURCE_LIMIT)
        public = session.source('desktop/macos-installed-inputs/fixed-arm-carrier-origin-public.json', 64405, ORIGIN['qualificationEvidenceSha256'])
        origin_public_data(public)
        modules = {}
        for p in SOURCE_FILES:
            source = session.source(p, SOURCE_MODULE_LIMIT)
            if p.startswith('desktop/tools/') and p.endswith('.py') and Path(p).name != 'macos_e2_native_fixture.py':
                modules[Path(p).name] = load_module('_mrk_resume_' + Path(p).stem, root / p, source)
        certificate, size, digest = SIGNING_CERTIFICATE
        session.source(certificate, size, digest)
        session.stager = modules['stage_macos_installed.py']
        session.owner = modules['macos_aqua_qualification.py'].load_owner(root)
        session.host_module = modules['macos_xcode_host_preparation.py']
        session.host = session.host_module.DarwinAPI(clock, target=TARGETS[0])
        session.run_id, session.run_attempt = env['GITHUB_RUN_ID'], env['GITHUB_RUN_ATTEMPT']
        session.host.waitable_sigchld()
        session.python = os.path.realpath(sys.executable)
        # Keep all private host originals until every native command and POST
        # closes. This sibling is retained until hosted job teardown, not retired.
        host_root = Path(env['MRK_MACOS_WORK']) / 'host-python'
        host_entry, host_body = session.quota.call(session.outer, 'file', host_root / 'host-binding.json', 32768, modes=(0o600,))
        host_binding = decode(host_body)
        def directory(path):
            held = session.quota.call(session.outer, 'directory', path)
            return held['identity'], os.listdir(held['fd'])
        def read_file(path, limit):
            held, body = session.quota.call(session.outer, 'file', path, limit)
            return held['identity'], body
        host_snapshot_value, host_cfg = host_snapshot(host_root, directory, read_file, sidecar=True)
        host_context = {'executable': session.python, 'prefix': sys.prefix, 'basePrefix': sys.base_prefix,
                        'baseExecutable': str(Path(sys._base_executable).resolve())}
        host_output_bytes = host_selection_data(host_binding, host_snapshot_value, host_cfg, host_root, host_context,
                                               env['GITHUB_SHA'], env['GITHUB_RUN_ID'], env['GITHUB_RUN_ATTEMPT']) + len(host_body)
        host_retained_bytes = len(host_body) + len(host_cfg)
        session.point()
        def admit_tool(tool):
            tool_uid = os.stat(tool, follow_symlinks=False).st_uid
            need(tool_uid in (0, os.getuid()), 'resume-tool-owner')
            entry, content = session.quota.call(session.outer, 'file', Path(tool), 64 << 20, uid=tool_uid, modes=(0o555, 0o755, 0o4555, 0o4755))
            need(content, 'resume-tool-original')
        # Explicit closed call sites make a denied file observable by exact
        # SOURCE location; ordinary roles keep their arguments, guards and order.
        admit_tool(session.python)
        admit_tool('/usr/bin/hdiutil')
        admit_tool('/usr/bin/vm_stat')
        admit_tool('/usr/bin/openssl')
        admit_tool('/usr/bin/codesign')
        sudo = session.quota.book(lambda: FixedSudoOriginals(
            modules['macos_xcode_host_preparation.py'], session.host, clock, os.getuid()))
        sudo.acquire(session.quota)
        admit_tool('/usr/sbin/installer')
        ca_body = admit_pinned_tls_roots(session)
        session.token = env.get('GITHUB_TOKEN'); request_headers(authenticated=True, token=session.token)
        session.environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC',
                               'HOME': '/Users/runner', 'TMPDIR': str(work) + '/'}
        leaf = next(content for entry, content in session.sources if str(entry['path']).endswith('/macos-install-producer-certificates/leaf.der'))
        session.signing_identity = {'teamIdentifier': '7CGZ2343AA', 'leafCertificateSha1': hashlib.sha1(leaf).hexdigest(), 'leafCertificateSha256': sha(leaf)}
        need(session.signing_identity['leafCertificateSha1'] == '5effa7d19bbe005b19c1617833cbe22186c2af96', 'resume-original-signing-certificate')
        STATE['phase'] = 'resource-admission'
        memory_call = session.command('memory', ['/usr/bin/vm_stat'], 10)
        page_size, physical = host_memory_data(session.host, clock)
        memory = memory_data(memory_call.stdout, memory_call.stderr, memory_call.returncode, page_size=page_size, physical_bytes=physical)
        retained = sum(len(content) for _, content in session.sources) + len(ca_body) + host_retained_bytes + (2 << 20)
        required_memory = acquisition_memory_requirement(retained)
        session.memory_base, session.required_disk = required_memory, (3 << 30) + 2 * ORIGIN['artifactBytes'] + host_output_bytes
        session.allocation_samples, session.cpio_window = 0, None
        disk = os.fstatvfs(session.parent['fd'])
        STATE['resourceAdmission'] = resource_admission_data(memory['availableEstimateBytes'],required_memory,
                    disk.f_bavail * disk.f_frsize,session.required_disk)
        need(STATE['resourceAdmission']['memorySufficient'], 'resume-resource-memory-admission')
        need(STATE['resourceAdmission']['diskSufficient'], 'resume-resource-disk-admission')
        STATE['phase'] = 'acquire-carrier'
        artifact = session.acquire_fixed(); preview = preview_data(artifact['PREVIEW.json'], session.stager)
        session.memory_base = post_acquisition_memory_requirement(retained)
        session.preview_bytes, session.preview_sha = len(artifact['PREVIEW.json']), sha(artifact['PREVIEW.json'])
        session.install_image(artifact['MobileReleaseKit.dmg'], preview)
        session.point(); session.clock.finality = True
        session.retire(); need(session.quota.finish(), 'resume-original-final-closes'); session.clock.check()
        STATE['originalClosesKnown'] = True
        STATE['workloadsKnownSettled'] = all(v['returned'] and v['capturesSettled'] for v in session.calls)
        need(STATE['workloadsKnownSettled'] and session.installer_zero and session.readback_known and session.mount_detached, 'resume-original-terminal-finality')
        STATE['phase'] = 'complete'
        receipt = {'schemaVersion': 1, 'scope': scope, 'producerSource': ORIGIN['source'], 'producerTree': ORIGIN['tree'],
                'producerRunId': ORIGIN['runId'], 'producerRunAttempt': ORIGIN['runAttempt'], 'producerJobId': ORIGIN['jobId'],
                'artifactId': ORIGIN['artifactId'], 'artifactSha256': ORIGIN['artifactSha256'], 'consumerSource': env['GITHUB_SHA'],
                'consumerRunId': env['GITHUB_RUN_ID'], 'consumerRunAttempt': env['GITHUB_RUN_ATTEMPT'], 'target': TARGETS[0],
                'originalInstallerReturnedZero': True, 'sameRequestReadback': True, 'originalMountDetached': True,
                'originalClosesKnown': True, 'workloadsKnownSettled': True, 'privateOutputsRetired': True,
                'receiptAuthority': 'same-consumer-owned-installer-and-readback-not-old-status', 'productReady': False,
                'p0Qualified': False, 'intelQualified': False}
        if normal_batch is not None:
            receipt['normalBatch'] = normal_batch
            if normal_batch == 'saved-version-recovery':
                receipt['savedVersionRuntimeOrigin'] = {'scope':'fixed-original-release-saved-version-runtime-v1',
                    'sourceCommit':ORIGIN['source'],'release':ORIGIN['release'],
                    'runtimeManifestSha256':session.installation['runtimeManifestSha256'],
                    'installationInventorySha256':session.installation['inventorySha256']}
        return receipt
    except BaseException as error:
        primary = error
        if STATE['firstFailurePhase'] is None:
            STATE['firstFailurePhase'] = STATE['phase']
        raise
    finally:
        settled = False
        try: settled = quota.finish()
        except BaseException:
            if primary is None: raise
            BaseException.add_note(primary, 'resume-original-final-closes')
        STATE['originalClosesKnown'] = settled
        if not settled:
            if primary is None: raise Refused('resume-original-final-closes')
            BaseException.add_note(primary, 'resume-original-final-closes')



def projection_data(install, build, test, summary, counts, facts, source, run_id, attempt):
    """Only joined finite receipts; no XCTest text, image, archive, URL or capture."""
    need(type(install) is dict and install.get('scope') == SCOPE and install.get('producerSource') == ORIGIN['source']
         and install.get('producerTree') == ORIGIN['tree'] and install.get('artifactId') == ORIGIN['artifactId']
         and install.get('artifactSha256') == ORIGIN['artifactSha256']
         and (install.get('consumerSource'), install.get('consumerRunId'), install.get('consumerRunAttempt')) == (source, run_id, attempt)
         and install.get('target') == TARGETS[0]
         and all(install.get(k) is True for k in ('originalInstallerReturnedZero', 'sameRequestReadback', 'originalMountDetached',
              'originalClosesKnown', 'workloadsKnownSettled', 'privateOutputsRetired'))
         and all(install.get(k) is False for k in ('productReady', 'p0Qualified', 'intelQualified')), 'resume-projection-installer')
    rosters=[]
    for row, phase, seconds, bundle in ((build, 'build', 450, None),
         (test, 'test', 1245, 'ios-unsigned-archive-test.xcresult'), (summary, 'summary', 90, 'ios-unsigned-archive-test.xcresult')):
        need(type(row) is dict and row.get('sourceCommit') == source and row.get('target') == TARGETS[0]
             and row.get('fixedCarrierResumeScope') == SCOPE and row.get('applicationSourceCommit') == ORIGIN['source']
             and all(row.get(k) is False for k in ('currentProductQualified', 'p0Qualified', 'intelQualified'))
             and row.get('sourcePrePostMatched') is True and row.get('originalCommandReturned') is True
             and row.get('normalPhase' if phase == 'test' else 'phase') == phase and row.get('resultBundle') == bundle
             and type(row.get('originalTestReturncode' if phase == 'test' else 'originalReturncode')) is int
             and row['originalTestReturncode' if phase == 'test' else 'originalReturncode'] == 0
             and row.get('receiptPolicy') == 'exclusive0600-readback-consuming-close', 'resume-projection-original')
        roster=row.get('sourceRosterSha256');need(type(roster) is str and re.fullmatch(r'[0-9a-f]{64}',roster), 'resume-projection-source-roster')
        rosters.append(roster)
        clock=row.get('phaseClock');need(type(clock) is dict and clock.get('postCloseDeadlineRequired') is True
             and all(type(clock.get(k)) is str and re.fullmatch(r'0|[1-9][0-9]{0,19}',clock[k]) for k in ('startNs','deadlineNs','beforePublicationNs')),
             'resume-projection-clock')
        start,end,before=(int(clock[k]) for k in ('startNs','deadlineNs','beforePublicationNs'))
        need(end-start==seconds*1_000_000_000 and start<=before<end, 'resume-projection-clock')
        commands=row.get('commands');need(type(commands) is list and commands
             and all(type(v) is dict and type(v.get('returncode')) is int and v['returncode']==0 for v in commands), 'resume-projection-commands')
    need(rosters[0]==rosters[1]==rosters[2] and test.get('originalClosesCompleted') is True
         and test.get('originalProductsPrePostMatched') is True and test.get('strictCodesignOriginalZero') is True,
         'resume-projection-runner-finality')
    expected={'totalTestCount':1,'passedTests':1,'failedTests':0,'skippedTests':0,'expectedFailures':0}
    need(type(counts) is dict and all(type(counts.get(k)) is int and counts[k]==v for k,v in expected.items())
         and summary.get('iosUnsignedTestCounts')==expected and test.get('iosUnsignedObservation')==facts,
         'resume-projection-one-test')
    # The unchanged normal runner's ios_unsigned_facts enforces the complete
    # marker shape; this projection exports only a fixed summary of that result.
    need(type(facts) is dict and facts.get('sourceCommit')==source and facts.get('scope')=='one-ordinary-local-unsigned-ios-archive'
         and all(facts.get(k) is True for k in ('nativeResultDisplayed','outputPostMatched','originalsClosed','normalQuitObserved','successBeforeCutoff'))
         and all(facts.get(k) is False for k in ('signed','ipaExported','releaseQualified')), 'resume-projection-ui-facts')
    return {'schemaVersion':1,'scope':SCOPE,'producerSource':ORIGIN['source'],'producerTree':ORIGIN['tree'],
        'producerRunId':ORIGIN['runId'],'producerRunAttempt':ORIGIN['runAttempt'],'producerJobId':ORIGIN['jobId'],
        'carrierArtifactId':ORIGIN['artifactId'],'carrierArtifactSha256':ORIGIN['artifactSha256'],
        'harnessSource':source,'consumerRunId':run_id,'consumerRunAttempt':attempt,'target':TARGETS[0],
        'freshInstallerReadback':'passed','currentHarnessBuild':'passed','unsignedIOSArchiveAndQuit':'passed',
        'sourceRosterSha256':rosters[0],'testCounts':expected,'rawTextExported':False,
        'currentProductQualified':False,'p0Qualified':False,'intelQualified':False,'signedIOSExportQualified':False}


def project_main():
    env=os.environ
    need(env.get('GITHUB_REPOSITORY')==REPOSITORY and env.get('GITHUB_REF')==ENROLLMENT_REF
         and env.get('GITHUB_SHA')==env.get('GITHUB_WORKFLOW_SHA') and env.get('GITHUB_SHA')!=ORIGIN['source']
         and re.fullmatch(r'[0-9a-f]{40}',env.get('GITHUB_SHA',''))
         and env.get('GITHUB_WORKFLOW_REF')==REPOSITORY+'/'+RESUME_WORKFLOW+'@'+ENROLLMENT_REF,
         'resume-projection-context')
    root=Path(env['MRK_MACOS_WORK'])/'normal-ui'
    need(re.fullmatch(r'/Users/runner/work/_temp/mrk-macos-installed\.[A-Za-z0-9]{8}/normal-ui',str(root)), 'resume-projection-work')
    started=time.monotonic_ns(); originals=[];primary=None
    def read(name,cap):
        need(time.monotonic_ns()<started+10_000_000_000, 'resume-projection-read-clock')
        path=root/name;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);originals.append((fd,path,None))
        before=identity(os.fstat(fd));originals[-1]=(fd,path,before)
        need(stat.S_ISREG(before[2]) and stat.S_IMODE(before[2])==0o600 and before[3:6]==(os.getuid(),os.getgid(),1)
             and 0<before[6]<=cap and identity(os.stat(path,follow_symlinks=False))==before, 'resume-projection-file')
        data=os.pread(fd,before[6]+1,0)
        need(len(data)==before[6] and not os.pread(fd,1,before[6]) and identity(os.fstat(fd))==before, 'resume-projection-file-post')
        return data
    try:
        for name in ('build.status','ios-unsigned-archive-test.status','ios-unsigned-archive-summary.status'):
            need(read(name,16)==b'0\n','resume-projection-caller-status')
        names=('fixed-carrier-install.json','build.command-admission.json','ios-unsigned-archive-test.runner-admission.json',
            'ios-unsigned-archive-summary.command-admission.json','ios-unsigned-archive-summary.json','ios-unsigned-archive.facts.json')
        rows=[decode(read(name,262144 if name=='ios-unsigned-archive-summary.json' else 32768),
                     allow_finite_floats=name=='ios-unsigned-archive-summary.json') for name in names]
        result=projection_data(*rows,env['GITHUB_SHA'],env['GITHUB_RUN_ID'],env['GITHUB_RUN_ATTEMPT'])
        for fd,path,before in originals:
            need(identity(os.fstat(fd))==before==identity(os.stat(path,follow_symlinks=False)), 'resume-projection-held-post')
    except BaseException as error:
        primary=error;raise
    finally:
        failures=[]
        for fd,path,before in originals:
            try:os.close(fd)
            except BaseException:failures.append('resume-projection-close')
        if failures:
            if primary is None:raise Refused('resume-projection-close')
            BaseException.add_note(primary,'resume-projection-close')
    need(time.monotonic_ns()<started+10_000_000_000, 'resume-projection-final-clock')
    return result



# Closed first-party SOURCE locations only. These exact leaves are compiled only
# after checkout-owned bootstrap and input admission. No new I/O,
# traceback rendering, error args/notes/locals or private filenames are used.
# Diagnostic line numbers are bounded integers, not source-file size snapshots.
FAULT_SOURCE_LINES = dict.fromkeys((*SOURCE_FILES, 'desktop/tools/macos_fixed_carrier_resume.py'), 100_000)
FAULT_CLASSES = ('Refused', 'AttributeError', 'TypeError', 'ValueError', 'ImportError', 'ModuleNotFoundError', 'OSError', 'FileNotFoundError', 'PermissionError', 'RuntimeError', 'KeyError', 'AssertionError', 'KeyboardInterrupt', 'SystemExit', 'ProcessError', 'ProcessInterrupted', 'SyntaxError', 'IndentationError', 'TabError', 'other')


def unavailable_location():
    return {'state': 'unavailable', 'exceptionClass': None, 'frames': [],
            'truncated': False, 'foreignFramesExcluded': False}


def location_data(value):
    """Strict finite failure-only DATA, never an authorization or cleanup proof."""
    empty = unavailable_location()
    if type(value) is not dict or set(value) != set(empty): return empty
    if (value['state'] not in ('observed', 'unavailable')
        or value['exceptionClass'] is not None and value['exceptionClass'] not in FAULT_CLASSES
        or type(value['truncated']) is not bool or type(value['foreignFramesExcluded']) is not bool
        or type(value['frames']) is not list or len(value['frames']) > 8): return empty
    frames = []
    for row in value['frames']:
        if (type(row) is not dict or set(row) != {'source', 'line'}
            or type(row['source']) is not str or row['source'] not in FAULT_SOURCE_LINES
            or type(row['line']) is not int or not 0 < row['line'] <= FAULT_SOURCE_LINES[row['source']]): return empty
        frames.append({'source': row['source'], 'line': row['line']})
    if (value['state'] == 'observed') != bool(frames): return empty
    return dict(value, frames=frames)


def failure_location(error):
    """At most64 scanned SOURCE frames; retain first4 and latest4 visited."""
    try:
        result = unavailable_location()
        name = type(error).__name__
        result['exceptionClass'] = name if name in FAULT_CLASSES else 'other'
        root = Path(__file__).absolute().parents[2]
        lookup = {str(root / p): p for p in FAULT_SOURCE_LINES}
        tb = error.__traceback__; scanned = 0
        while tb is not None and scanned < 64:
            relative = lookup.get(tb.tb_frame.f_code.co_filename)
            line = tb.tb_lineno
            if relative is not None and type(line) is int and 0 < line <= FAULT_SOURCE_LINES[relative]:
                result['frames'].append({'source': relative, 'line': line})
                if len(result['frames']) > 8:
                    del result['frames'][4]; result['truncated'] = True
            else: result['foreignFramesExcluded'] = True
            tb = tb.tb_next; scanned += 1
        result['truncated'] = result['truncated'] or tb is not None
        if result['frames']: result['state'] = 'observed'
        return location_data(result)
    except BaseException:
        # Diagnostic failure must not replace the original error/finality state.
        return unavailable_location()


def finite_failure_data(native, statuses, ui):
    """Non-authorizing fixed observations, never raw JSON/error text forwarding."""
    need(type(statuses) is dict and set(statuses)=={'installer','harness','ios','summary','result'}, 'resume-diagnostic-status-roster')
    rows={}
    for role,value in statuses.items():
        need(value is None or type(value)is int and 0<=value<=255,'resume-diagnostic-status-value')
        rows[role]={'state':'unavailable' if value is None else 'observed','returncode':value}
    native_row={'state':'unavailable','phase':None,'originalClosesKnown':None,'workloadsKnownSettled':None,'privateOutputsRetired':None,'failureLocation':unavailable_location(),'resourceAdmission':None,'installerObservation':None}
    allowed=('admission','initial-source','attach','producer-signature','installer','readback','detach-finality',
             'resource-admission','acquire-carrier','complete')
    if type(native)is dict and native.get('schemaVersion')==1 and native.get('scope')==SCOPE and native.get('accepted')is False:
        phase=native.get('firstFailurePhase') or native.get('phase')
        if phase in allowed and type(phase)is str:
            native_row['state']='observed-failure';native_row['phase']=phase
            native_row['failureLocation']=location_data(native.get('failureLocation'))
            native_row['resourceAdmission']=resource_projection_data(native.get('resourceAdmission'))
            if phase == 'installer': native_row['installerObservation']=installer_observation_projection_data(native.get('installerObservation'))
            for key in ('originalClosesKnown','workloadsKnownSettled','privateOutputsRetired'):
                native_row[key]=native.get(key) if type(native.get(key))is bool else None
    stages={'state':'unavailable','events':[]};owner={'dispatched':None,'contained':None,'cleanupComplete':None}
    exception=None;site=None
    if type(ui)is dict:
        if ui.get('scope')=='normal-macos-ui-failure-diagnostic-only' and ui.get('phase')=='test' and ui.get('selection')=='ios-unsigned-archive-test.xcresult':
            candidate=ui.get('iosUnsignedStages');names=tuple('ios-unsigned-'+v for v in ('fixture','launch','project','review','original-result','close'))
            if type(candidate)is dict and candidate.get('state')in ('unavailable','refused','observed','absent') and type(candidate.get('events'))is list and len(candidate['events'])<=12:
                events=[]
                for event in candidate['events']:
                    if type(event)is not dict or set(event)!={'stage','result'} or event.get('stage')not in names or event.get('result')not in ('started','passed','failed'):
                        events=None;break
                    events.append({'stage':event['stage'],'result':event['result']})
                if events is not None:stages={'state':candidate['state'],'events':events}
        elif ui.get('scope')=='normal-macos-ui-admission-diagnostic-only' and ui.get('status')=='observed-exception-only':
            labels=('Refused','AttributeError','TypeError','ValueError','ImportError','ModuleNotFoundError','OSError','FileNotFoundError','PermissionError',
                    'RuntimeError','KeyError','AssertionError','KeyboardInterrupt','SystemExit','ProcessError','ProcessInterrupted','other')
            if ui.get('exceptionClass')in labels and ui.get('stage')in ('request','context','loader','phase','execute','diagnostic','publication','finalize'):
                exception=ui['exceptionClass'];site=ui['stage']
                found=ui.get('ownerFailure')
                if type(found)is dict:
                    owner={k:found.get(k)if type(found.get(k))is bool else None for k in owner}
    return {'schemaVersion':1,'scope':SCOPE,'purpose':'finite-current-consumer-observation-only','callerStatuses':rows,'native':native_row,
        'iosUnsignedStages':stages,'admissionExceptionClass':exception,'admissionStage':site,'ownerFailure':owner,
        'successInferred':False,'unknownStateNotConvertedToCleanup':True,'rawTextExported':False,'productReady':False,'p0Qualified':False,'intelQualified':False}


def diagnostic_main():
    env=os.environ;root=Path(env['MRK_MACOS_WORK'])/'normal-ui'
    need(re.fullmatch(r'/Users/runner/work/_temp/mrk-macos-installed\.[A-Za-z0-9]{8}/normal-ui',str(root)), 'resume-diagnostic-work')
    started=time.monotonic_ns();fds=[];primary=None
    def optional(name,cap):
        need(time.monotonic_ns()<started+10_000_000_000,'resume-diagnostic-clock')
        path=root/name
        try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        except FileNotFoundError:return None
        fds.append((fd,path,None));before=identity(os.fstat(fd));fds[-1]=(fd,path,before)
        need(stat.S_ISREG(before[2])and stat.S_IMODE(before[2])==0o600 and before[3:6]==(os.getuid(),os.getgid(),1) and 0<=before[6]<=cap,
             'resume-diagnostic-file')
        body=os.pread(fd,before[6]+1,0)
        need(len(body)==before[6]and not os.pread(fd,1,before[6]) and identity(os.fstat(fd))==before==identity(os.stat(path,follow_symlinks=False)),
             'resume-diagnostic-original-post')
        return body
    try:
        statuses={}
        for role,name in (('harness','build.status'),('ios','ios-unsigned-archive-test.status'),('summary','ios-unsigned-archive-summary.status')):
            body=optional(name,16);statuses[role]=None
            if body is not None and re.fullmatch(rb'(0|[1-9][0-9]{0,2})\n',body) and int(body)<=255:statuses[role]=int(body)
        for role,key in (('installer','MRK_FIXED_INSTALL_OUTCOME'),('result','MRK_FIXED_RESULT_OUTCOME')):
            value=env.get(key);statuses[role]=0 if value=='success' else None # failed/skipped/cancelled never fabricate a returncode.
        body=optional('fixed-carrier-install.json',16384);native=decode(body)if body else None
        ui=None
        for name in ('ios-unsigned-archive-test.failure-diagnostics.json','ios-unsigned-archive-summary.failure-diagnostics.json','build.failure-diagnostics.json'):
            body=optional(name,4096)
            if body:
                candidate=decode(body)
                if type(candidate)is dict and candidate.get('scope')in ('normal-macos-ui-failure-diagnostic-only','normal-macos-ui-admission-diagnostic-only'):
                    ui=candidate;break
        result=finite_failure_data(native,statuses,ui)
        result.update(producerSource=ORIGIN['source'],consumerSource=env['GITHUB_SHA'],consumerRunId=env['GITHUB_RUN_ID'],consumerRunAttempt=env['GITHUB_RUN_ATTEMPT'])
        for fd,path,before in fds:need(identity(os.fstat(fd))==before==identity(os.stat(path,follow_symlinks=False)),'resume-diagnostic-terminal-post')
    except BaseException as error:primary=error;raise
    finally:
        errors=[]
        for fd,path,before in fds:
            try:os.close(fd)
            except BaseException:errors.append(1)
        if errors:
            if primary is None:raise Refused('resume-diagnostic-close')
            BaseException.add_note(primary,'resume-diagnostic-close')
    need(time.monotonic_ns()<started+10_000_000_000,'resume-diagnostic-final-clock')
    return result


def cleanup_main():
    """Existing symlink-safe fixed-output cleanup, only after joined success.

    Protected installed state/vault and separately retained Swift /private/tmp
    fixture originals are outside this cleanup authority, never glob-discovered.
    """
    import shutil
    env=os.environ
    need(env.get('MRK_FIXED_RESULT_OUTCOME')=='success' and env.get('MRK_FIXED_UPLOAD_OUTCOME')=='success'
         and shutil.rmtree.avoids_symlink_attacks,'resume-cleanup-success-authority')
    result=project_main() # Same genuine current0/status/admission/marker joins before deletion.
    work=Path(env['MRK_MACOS_WORK']);normal=work/'normal-ui';fds=[];primary=None
    try:
        for path in (work,normal):
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY|os.O_CLOEXEC);fds.append((fd,path,identity(os.fstat(fd))[:5]))
        wfd,_,wbefore=fds[0];nfd,_,nbefore=fds[1]
        for fd,path,before in fds:
            need(stat.S_ISDIR(before[2])and stat.S_IMODE(before[2])==0o700 and before[3:5]==(os.getuid(),os.getgid())
                 and identity(os.stat(path,follow_symlinks=False))[:5]==before,'resume-cleanup-parent')
        binding_fd=os.open('consumer-work-binding.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=nfd);fds.append((binding_fd,normal/'consumer-work-binding.json',identity(os.fstat(binding_fd))))
        original=fds[-1][2];need(stat.S_ISREG(original[2])and stat.S_IMODE(original[2])==0o600 and original[3:6]==(os.getuid(),os.getgid(),1)
             and 0<original[6]<=4096,'resume-cleanup-binding-original')
        body=os.pread(binding_fd,original[6]+1,0);need(len(body)==original[6]and not os.pread(binding_fd,1,original[6]),'resume-cleanup-binding-read')
        binding=decode(body)
        need(binding.get('source')==env['GITHUB_SHA'] and binding.get('runId')==env['GITHUB_RUN_ID'] and binding.get('runAttempt')==env['GITHUB_RUN_ATTEMPT']
             and binding.get('workIdentity')==list(wbefore)and binding.get('normalIdentity')==list(nbefore),'resume-cleanup-admitted-root')
        def post():
            for fd,path,before in fds:need(identity(os.fstat(fd))[:len(before)]==before==identity(os.stat(path,follow_symlinks=False))[:len(before)],'resume-cleanup-parent-post')
        post()
        # Same standard fd-based shutil primitive used in the original installed
        # workflow, narrowed to this consumer's three known settled output roots.
        for name in ('DerivedData','ios-unsigned-archive-test.xcresult','tmp'):
            info=os.stat(name,dir_fd=nfd,follow_symlinks=False)
            need(stat.S_ISDIR(info.st_mode)and info.st_uid==os.getuid()and info.st_dev==wbefore[0],'resume-cleanup-directory')
            post();shutil.rmtree(name,dir_fd=nfd);post()
        for name in ('build.log','build.stderr','ios-unsigned-archive-test.log','ios-unsigned-archive-test.stderr',
                     'ios-unsigned-archive-summary.json','ios-unsigned-archive-summary.stderr'):
            info=os.stat(name,dir_fd=nfd,follow_symlinks=False)
            need(stat.S_ISREG(info.st_mode)and info.st_uid==os.getuid()and info.st_nlink==1 and info.st_dev==wbefore[0],'resume-cleanup-private-output')
            post();os.unlink(name,dir_fd=nfd);post()
        return {'schemaVersion':1,'scope':SCOPE,'taskHarnessOutputsRetired':True,'installedAppRetained':True,
                'separateSyntheticFixtureRetired':False,'sharedServicesStopped':False,'productReady':False}
    except BaseException as error:primary=error;raise
    finally:
        errors=[]
        for fd,path,before in reversed(fds):
            try:os.close(fd)
            except BaseException:errors.append(1)
        if errors:
            if primary is None:raise Refused('resume-cleanup-close')
            BaseException.add_note(primary,'resume-cleanup-close')

def normal_cleanup_main():
    """Existing symlink-safe fixed-output cleanup, only after joined success.

    Protected installed state/vault and separately retained Swift /private/tmp
    fixture originals are outside this cleanup authority, never glob-discovered.
    """
    import shutil
    env=os.environ
    need(env.get('MRK_FIXED_RESULT_OUTCOME')=='success' and env.get('MRK_FIXED_UPLOAD_OUTCOME')=='success'
         and shutil.rmtree.avoids_symlink_attacks,'resume-cleanup-success-authority')
    result=normal_batch_project_main() # Same genuine current0/status/admission/marker joins before deletion.
    _,batch,normal=normal_projection_context()
    work=normal.parent;fds=[];primary=None
    try:
        for path in (work,normal):
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY|os.O_CLOEXEC);fds.append((fd,path,identity(os.fstat(fd))[:5]))
        wfd,_,wbefore=fds[0];nfd,_,nbefore=fds[1]
        for fd,path,before in fds:
            need(stat.S_ISDIR(before[2])and stat.S_IMODE(before[2])==0o700 and before[3:5]==(os.getuid(),os.getgid())
                 and identity(os.stat(path,follow_symlinks=False))[:5]==before,'resume-cleanup-parent')
        binding_fd=os.open('consumer-work-binding.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=nfd);fds.append((binding_fd,normal/'consumer-work-binding.json',identity(os.fstat(binding_fd))))
        original=fds[-1][2];need(stat.S_ISREG(original[2])and stat.S_IMODE(original[2])==0o600 and original[3:6]==(os.getuid(),os.getgid(),1)
             and 0<original[6]<=4096,'resume-cleanup-binding-original')
        body=os.pread(binding_fd,original[6]+1,0);need(len(body)==original[6]and not os.pread(binding_fd,1,original[6]),'resume-cleanup-binding-read')
        binding=decode(body)
        need(binding.get('source')==env['GITHUB_SHA'] and binding.get('runId')==env['GITHUB_RUN_ID'] and binding.get('runAttempt')==env['GITHUB_RUN_ATTEMPT']
             and binding.get('workIdentity')==list(wbefore)and binding.get('normalIdentity')==list(nbefore),'resume-cleanup-admitted-root')
        def post():
            for fd,path,before in fds:need(identity(os.fstat(fd))[:len(before)]==before==identity(os.stat(path,follow_symlinks=False))[:len(before)],'resume-cleanup-parent-post')
        post()
        # Same standard fd-based shutil primitive used in the original installed
        # workflow, narrowed to this consumer's three known settled output roots.
        for name in ('DerivedData',*[row[0] for row in NORMAL_FAMILIES[batch]],'tmp'):
            info=os.stat(name,dir_fd=nfd,follow_symlinks=False)
            need(stat.S_ISDIR(info.st_mode)and info.st_uid==os.getuid()and info.st_dev==wbefore[0],'resume-cleanup-directory')
            post();shutil.rmtree(name,dir_fd=nfd);post()
        outputs=['build.log','build.stderr']
        for _,test_stem,summary_stem,_,_ in NORMAL_FAMILIES[batch]:
            outputs.extend((test_stem+'.log',test_stem+'.stderr',summary_stem+'.json',summary_stem+'.stderr'))
        for name in outputs:
            info=os.stat(name,dir_fd=nfd,follow_symlinks=False)
            need(stat.S_ISREG(info.st_mode)and info.st_uid==os.getuid()and info.st_nlink==1 and info.st_dev==wbefore[0],'resume-cleanup-private-output')
            post();os.unlink(name,dir_fd=nfd);post()
        return {'schemaVersion':1,'scope':NORMAL_SCOPE,'normalBatch':batch,'taskHarnessOutputsRetired':True,'installedAppRetained':True,
                'separateSyntheticFixtureRetired':False,'sharedServicesStopped':False,'productReady':False}
    except BaseException as error:primary=error;raise
    finally:
        errors=[]
        for fd,path,before in reversed(fds):
            try:os.close(fd)
            except BaseException:errors.append(1)
        if errors:
            if primary is None:raise Refused('resume-cleanup-close')
            BaseException.add_note(primary,'resume-cleanup-close')

if __name__ == '__main__':
    if sys.argv[1:] == ['acquire']:
        # Never native install in the transport child.
        result = acquisition_main()
        sys.stdout.buffer.write(canonical(result) + b'\n')
    elif sys.argv[1:] in (['diagnostic'], ['cleanup']):
        try:result=diagnostic_main()if sys.argv[1]=='diagnostic'else cleanup_main()
        except BaseException:
            sys.stdout.buffer.write(canonical({'schemaVersion':1,'scope':SCOPE,'accepted':False,'phase':'finite-observation-or-cleanup','productReady':False})+b'\n')
            raise SystemExit(1)from None
        sys.stdout.buffer.write(canonical(result)+b'\n')
    elif sys.argv[1:] == ['project']:
        try: result = project_main()
        except BaseException:
            sys.stdout.buffer.write(canonical({'schemaVersion':1,'scope':SCOPE,'accepted':False,'phase':'projection','productReady':False,'p0Qualified':False})+b'\n')
            raise SystemExit(1) from None
        sys.stdout.buffer.write(canonical(result)+b'\n')
    elif sys.argv[1:] in (['project-normal-batch'],['diagnostic-normal'],['cleanup-normal']) or (len(sys.argv) == 3 and sys.argv[1] == 'project-normal'):
        scope,batch = NORMAL_SCOPE,None
        try:
            _,batch,_ = normal_projection_context()
            result = (normal_project_main(sys.argv[2]+'.xcresult') if sys.argv[1] == 'project-normal' else
                      normal_batch_project_main() if sys.argv[1] == 'project-normal-batch' else
                      normal_diagnostic_main() if sys.argv[1] == 'diagnostic-normal' else normal_cleanup_main())
        except BaseException as error:
            sys.stdout.buffer.write(canonical({'schemaVersion':1,'scope':scope,'normalBatch':batch,'accepted':False,
                'phase':'finite-observation-or-cleanup' if sys.argv[1] in ('diagnostic-normal','cleanup-normal') else 'projection',
                **({'failureLocation':failure_location(error)} if sys.argv[1] in ('project-normal','project-normal-batch') else {}),
                'productReady':False,'currentProductQualified':False,'p0Qualified':False,'intelQualified':False})+b'\n')
            raise SystemExit(1) from None
        sys.stdout.buffer.write(canonical(result)+b'\n')
    elif sys.argv[1:]:
        raise SystemExit(2)
    else:
        try:
            result = main()
        except BaseException as error:
            # Fixed finite state only; no paths, tokens, inputs/captures or exception text.
            normal_batch = os.environ.get(NORMAL_BATCH_ENV)
            ordinary = os.environ.get('TEST_RUNNER_MRK_NORMAL_UI_FIXED_CARRIER_RESUME') == NORMAL_SCOPE and normal_batch in NORMAL_FAMILIES
            selection = {'normalBatch':normal_batch} if ordinary else {}
            sys.stdout.buffer.write(canonical({'schemaVersion': 1, 'scope': NORMAL_SCOPE if ordinary else SCOPE, **selection, 'accepted': False,
                'phase': STATE['phase'], 'firstFailurePhase': STATE['firstFailurePhase'],
                'failureLocation': failure_location(error), 'resourceAdmission': STATE['resourceAdmission'],
                'installerObservation': installer_observation_projection_data(STATE['installerObservation']),
                'originalClosesKnown': STATE['originalClosesKnown'],
                'workloadsKnownSettled': STATE['workloadsKnownSettled'], 'privateOutputsRetired': STATE['privateOutputsRetired'],
                'productReady': False, 'p0Qualified': False, 'intelQualified': False}) + b'\n')
            raise SystemExit(1) from None
        sys.stdout.buffer.write(canonical(result) + b'\n')
