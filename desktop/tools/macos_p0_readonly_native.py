"""Fixed read-only P0 artifact/DMG enrollment; never executes mounted payloads.

No arbitrary URL/tool/project selectors. Anchors remain SOURCE-owned and
unconfigured until independent genuine original qualification is available.
The ordinary CLI is not used: native commands use the existing C/A/W owner.
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
import urllib.error
import urllib.parse
import urllib.request
import ssl
import zipfile
import zlib

REPOSITORY = 'Apdelrahman1911/mobile-release-kit'
WORKFLOW = '.github/workflows/desktop-macos-installed.yml'
WORKFLOW_ID = 363563168
ENROLLMENT_REF = 'refs/heads/verify/desktop-macos-p0-readonly-enrollment'
TARGETS = ('aarch64-apple-darwin', 'x86_64-apple-darwin')
LIMIT = 512 << 20
OUTPUT_LIMIT = 2 << 20
TERMINAL_LIMIT = 64 << 10
SOURCE_LIMIT = 128 << 10
MAX_ORIGINALS = 96
PUBLIC_NAMES = ('arm64-installation-inventory.json', 'arm64-enrollment.json',
                'intel-installation-inventory.json', 'intel-enrollment.json', 'enrollment-native.json')
STATE = {'phase': 'admission', 'lastRole': None, 'originalClosesKnown': False,
         'privateOutputsRetired': False, 'workloadsKnownSettled': False}
SOURCE_PINS = {'desktop/tools/macos_e2_native_fixture.py': (390457, 'bcfbaf9ec8a8ae3253ef0ac91a1e73256de00a9adb6a9d280f64127b340cd51e'), 'desktop/tools/stage_macos_installed.py': (388486, '08a4609a37ea50426cfde297273b4e2ec53adc3727a86a13bdd5871988b3cfa2'), 'desktop/tools/macos_public_verification_evidence.py': (209883, '05ff6cf585f45601909afd14e7038df89adb8b56ee7411cb49428a0e8524a863'), 'desktop/tools/macos_aqua_qualification.py': (463990, 'd1ab3a83633c7e824277a4b316e2188877ecf03e8d54517a4275f931dd41290a'), 'desktop/tools/macos_xcode_host_preparation.py': (96477, 'd03cfd5c200564efd71050548ebac85b4f9b56fd3619027ec35ce6a1528e5376'), 'desktop/tools/macos_update_verification.py': (47996, '62bcf71974f6793f82f6ff3a48e045abe36af08c661085b564d58523fac51619'), 'src/mobile_release/owned_process.py': (9127, 'ba23e4c65a916c297190c028bd5fd934723ef496105a46ec45c2a2e4b2f22b59'), 'src/mobile_release/_command_process.py': (177438, 'ad1b7b7140d219674efd326ec529315fdf5a9fd55701a069d7f930a86e702a43'), 'src/mobile_release/_native_process.py': (62175, '70c380adde3c2bc06a0985761f0f877355bb56ef09ad506440da93fd4e4ba3b4'), 'src/mobile_release/cancellation.py': (32351, 'eff29612208b2d6d81afa5638fa998778b17f39107357bb7a2f954facdc2628a'), 'src/mobile_release/__init__.py': (144, '557bcb0cdcf7f7ef329f04f82cf388c746bb73eba34857b97782a8bcf2e596b2'), 'src/mobile_release/errors.py': (749, '26427cedbd05945c1a869af20228f9a04fe1e30d950a2dc246dd0795708a0853'), 'src/mobile_release/_lifetime_evidence.py': (19514, 'fcac01b5fefc60927cc6c1ebb4d14bb77df0de964c9965900313c573da92826d'), 'src/mobile_release/_store_lane_contract.py': (9500, '8726cf9bdb053b3d7f30eb9c8307c18239dc518476b2f895ef1610efa65e040e'), 'src/mobile_release/_store_lane_evidence.py': (17638, 'bcea0084032ffbd43c15f5682f456965aff812e5007d3211a5afe605fc4d5872'), 'desktop/tools/macos_p0_readonly_enrollment.py': (15931, 'c82994197e689cd5fe803d07202f8a8f2aa00ab469896098ed9171bdbd8e7485')}


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


def decode(body):
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
            need(item is None or type(item) in (bool, int), 'p0-json-scalar')
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


def metadata_data(run, job, artifact, row, role, target):
    need(role in ('qualification', 'carrier') and target in TARGETS and type(run) is dict and type(job) is dict and type(artifact) is dict,
         'p0-metadata-shape')
    selected = row['qualificationArtifact'] if role == 'qualification' else row
    need(type(run.get('id')) is int and str(run['id']) == row['runId']
         and type(run.get('run_attempt')) is int and str(run['run_attempt']) == row['runAttempt']
         and run.get('head_sha') == row['source'] and run.get('head_branch') == 'verify/desktop-macos-installed'
         and run.get('path') == WORKFLOW and run.get('workflow_id') == WORKFLOW_ID and run.get('status') == 'completed'
         and type(run.get('repository')) is dict and run['repository'].get('full_name') == REPOSITORY,
         'p0-metadata-run')
    need(type(job.get('id')) is int and str(job['id']) == row['jobId']
         and job.get('run_id') == run['id'] and job.get('head_sha') == row['source']
         and job.get('status') == 'completed' and job.get('conclusion') == 'success'
         and type(job.get('steps')) is list and 0 < len(job['steps']) <= 256
         and all(type(step) is dict and step.get('status') == 'completed' for step in job['steps']), 'p0-metadata-job')
    need(type(artifact.get('id')) is int and str(artifact['id']) == selected['artifactId']
         and artifact.get('name') == ('desktop-macos-installed-' + target + '-' + row['source'] + '-' + row['runId'] + '-' + row['runAttempt']
             if role == 'qualification' else 'mobile-release-kit-macos26-' + target + '-p0-carrier-input-' + row['source'] + '-' + row['runId'] + '-' + row['runAttempt'])
         and artifact.get('expired') is False and type(artifact.get('size_in_bytes')) is int
         and artifact['size_in_bytes'] == selected['artifactBytes']
         and artifact.get('digest') == 'sha256:' + selected['artifactSha256']
         and type(artifact.get('workflow_run')) is dict and artifact['workflow_run'].get('id') == run['id']
         and artifact['workflow_run'].get('head_sha') == row['source']
         and artifact['workflow_run'].get('head_branch') == run['head_branch'], 'p0-metadata-artifact')
    return selected


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


# Real EOF/CRC codec closure copied byte-exact from reviewed public collector.
TRANSPORT_LIMIT = LIMIT
MEMBERS = {'MobileReleaseKit.dmg': LIMIT, 'PREVIEW.json': 16384, 'public-verification-evidence.json': 128 << 10}


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


def resource_quote_data(row, source_bytes, update):
    quote = update.resource_quote_data(row)
    q = row['qualificationArtifact']
    retained = row['artifactBytes'] + sum(v['bytes'] for v in row['members']) + row['package']['bytes']
    retained += q['artifactBytes'] + q['memberBytes'] + source_bytes + OUTPUT_LIMIT
    return {'requiredAvailableMemoryBytes': quote['rawPayloadBytes'] + retained + (512 << 20) + (1 << 30),
            'requiredAvailableDiskBytes': quote['additionalDiskBytes'] + q['artifactBytes'] + q['memberBytes'] + (3 << 30),
            'maximumOriginals': MAX_ORIGINALS}


def resource_admission_data(memory, available_disk, quotes):
    need(type(memory) is dict and type(memory.get('availableEstimateBytes')) is int
         and type(available_disk) is int and type(quotes) is list and len(quotes) in (1, 2),
         'p0-resource-shape')
    required_memory = max(v['requiredAvailableMemoryBytes'] for v in quotes)
    # Both first-target ZIP/DMG originals remain retained during the second;
    # sum both conservative disk quotations with one unchanged system floor.
    required_disk = sum(v['requiredAvailableDiskBytes'] - (3 << 30) for v in quotes) + (3 << 30)
    need(memory['availableEstimateBytes'] >= required_memory and available_disk >= required_disk,
         'p0-resource-reserve')
    return {'requiredAvailableMemoryBytes': required_memory, 'requiredAvailableDiskBytes': required_disk,
            'serialTargetCount': len(quotes), 'osResourceReservation': False}


def qualified_rows_data(document, data, stager):
    result = []
    for target in TARGETS:
        try:
            row = data.anchors_data(document, target, stager)
        except data.Refused as error:
            # Only the explicit SOURCE-unconfigured other target can defer.
            # Any malformed/corrupted qualifier still refuses the whole task.
            if error.args != ('enrollment-qualified-target-unconfigured',): raise
            continue
        result.append((target, row))
    need(result, 'p0-qualification-anchors-unconfigured')
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
         and type(cfg['work']) is str and cfg['work'].startswith('/Users/runner/work/_temp/mrk-p0-readonly-')
         and str(Path(cfg['work'])) == os.path.normpath(cfg['work']), 'p0-child-admission')
    endpoint = cfg['endpoint'] / 1e9
    token = os.environ['MRK_P0_READ_TOKEN']
    phase, response, ca_fd, root_fd, output_fd = 'trust', None, None, None, None
    errors, primary = [], None
    try:
        ca_fd = os.open(cfg['caPath'], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        ca_before = identity(os.fstat(ca_fd))
        need(stat.S_ISREG(ca_before[2]) and ca_before[3] == 0 and ca_before[5] == 1
             and not ca_before[2] & 0o022 and 0 < ca_before[6] <= 2 << 20
             and identity(os.stat(cfg['caPath'], follow_symlinks=False)) == ca_before, 'p0-ca-original')
        ca = os.pread(ca_fd, ca_before[6] + 1, 0)
        need(len(ca) == ca_before[6] and sha(ca) == cfg['caSha256']
             and identity(os.fstat(ca_fd)) == ca_before, 'p0-ca-pin')
        context = ssl.create_default_context(cadata=ca.decode('ascii', 'strict'))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        need(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED, 'p0-tls-policy')
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


class Enrollment:
    def __init__(self, root, work, clock, factory, *, quota=None):
        self.root, self.work, self.clock = root, work, clock
        self.quota = OriginalQuota() if quota is None else quota
        self.outer = self.quota.book(factory)
        self.factory = factory
        self.calls, self.sources, self.private, self.results = [], [], {}, []
        self.output_bytes = 0
        self.public = {}
        self.expected_public = PUBLIC_NAMES
        self.parent = self.quota.call(self.outer, 'directory', work)

    def fresh_book(self):
        book = self.quota.book(self.factory)
        # Borrow ONLY authenticated outer ancestor originals, never a mount leaf.
        need(not book.entries and not book.directories, 'p0-fresh-book-shape')
        self.outer.check()
        borrowed = {path: entry for path, entry in self.outer.directories.items()
                    if path == self.work or path in self.work.parents}
        need(self.work in borrowed and all(entry['kind'] == 'directory' and entry['fd'] is not None
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
        need(role in ('memory', 'acquire-qualification', 'acquire-carrier', 'attach', 'detach'), 'p0-command-role')
        self.point(); timeout = self.clock.seconds(maximum)
        row = {'role': role, 'entered': True, 'returned': False, 'capturesSettled': False,
               'timeoutSeconds': timeout, 'outputLimitBytes': 65536}
        self.calls.append(row)
        STATE['lastRole'] = role
        try:
            result = self.owner.run_owned(argv, environ=self.environment if env is None else env, cwd=self.work,
                                          timeout=timeout, capture=True, text=False, output_limit=65536, cleanup=self.clock.finality)
        except BaseException as error:
            row['contained'] = getattr(error, 'contained', None) if type(getattr(error, 'contained', None)) is bool else None
            row['cleanupComplete'] = getattr(error, 'cleanup_complete', None) if type(getattr(error, 'cleanup_complete', None)) is bool else None
            raise
        need(result.args == argv and type(result.returncode) is int and type(result.stdout) is bytes
             and type(result.stderr) is bytes and len(result.stdout) <= 65536 and len(result.stderr) <= 65536, 'p0-original-command')
        row.update(returned=True, capturesSettled=True, returncode=result.returncode)
        self.point()
        return result

    def acquire(self, row, target, role):
        self.point()
        # Three actual filesystem originals in the fixed child: CA/work/output.
        self.quota.reserve(3)
        request = {'row': row, 'role': role, 'target': target, 'work': str(self.work),
                   'workIdentity': list(self.parent['identity']), 'caPath': self.ca_path, 'caSha256': self.ca_sha,
                   'endpoint': min(self.clock.work, self.clock.check() + 120_000_000_000)}
        encoded = canonical(request)
        need(len(encoded) <= 32768 and len(self.script) <= SOURCE_LIMIT, 'p0-child-original-request-bound')
        env = dict(self.environment, MRK_P0_REQUEST=encoded.decode('ascii'), MRK_P0_READ_TOKEN=self.token)
        # Exact held original SOURCE, not a second unchecked on-disk read.
        bootstrap = '__name__="__main__"; __file__=' + repr(str(self.root / 'desktop/tools/macos_p0_readonly_native.py')) + ';\n' + self.script.decode('utf-8')
        need(len(bootstrap.encode()) <= SOURCE_LIMIT + 1024, 'p0-child-source-bound')
        result = self.command('acquire-' + role, [self.python, '-I', '-S', '-B', '-c', bootstrap, 'acquire'], 120, env=env)
        need(result.returncode == 0 and result.stderr == b'', 'p0-acquisition-original')
        receipt = decode(result.stdout)
        selected = row['qualificationArtifact'] if role == 'qualification' else row
        need(receipt == {'schemaVersion': 1, 'role': role, 'target': target, 'bytes': selected['artifactBytes'],
             'sha256': selected['artifactSha256'], 'closedMetadataMatched': True, 'originalClosesKnown': True}, 'p0-acquisition-closed-report')
        name = ('arm64' if target == TARGETS[0] else 'intel') + '-' + role + '.zip'
        entry, body = self.quota.call(self.outer, 'file', self.work / name, selected['artifactBytes'], modes=(0o600,))
        need((len(body), sha(body)) == (selected['artifactBytes'], selected['artifactSha256']), 'p0-acquisition-parent-original')
        self.private[name] = entry['identity']
        if role == 'qualification':
            members = [{'name': selected['memberName'], 'bytes': selected['memberBytes'], 'sha256': selected['memberSha256']}]
        else: members = row['members']
        values = zip_data(body, {'kind': role, 'bytes': selected['artifactBytes'], 'sha256': selected['artifactSha256'], 'members': members}, self.clock)
        need(self.outer.read(entry) == body, 'p0-acquisition-original-post')
        return values

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
        os.fchmod(fd, 0o600); os.fsync(fd)
        entry['identity'] = identity(os.fstat(fd))
        need(entry['identity'][3:6] == (os.getuid(), os.getgid(), 1)
             and entry['identity'][6] == len(image) and stat.S_IMODE(entry['identity'][2]) == 0o600
             and self.outer.read(entry) == image, 'p0-image-copy-readback')
        self.outer.close(entry)
        need(entry['closed'], 'p0-image-copy-close')
        self.point()

    def inspect_image(self, image, row, target):
        self.point()
        label = 'arm64' if target == TARGETS[0] else 'intel'
        path, mount = self.work / (label + '.dmg'), self.work / (label + '-mount')
        self.publish_image(path, image)
        image_entry, original = self.quota.call(self.outer, 'file', path, len(image), modes=(0o600,))
        need(original == image, 'p0-image-published-original')
        self.private[path.name] = image_entry['identity']
        os.mkdir(mount.name, 0o700, dir_fd=self.parent['fd'])
        placeholder = self.fresh_book()
        leaf = self.quota.call(placeholder, 'directory', mount)
        before = leaf['identity']
        need(os.listdir(leaf['fd']) == [] and before[3:5] == (os.getuid(), os.getgid()), 'p0-empty-original-placeholder')
        placeholder.check(); need(placeholder.finish(), 'p0-placeholder-close')
        attached, device, mounted, primary, detached = False, None, None, None, False
        STATE['phase'] = 'attach'
        try:
            call = self.command('attach', ['/usr/bin/hdiutil', 'attach', '-readonly', '-nobrowse', '-owners', 'on',
                                         '-mountpoint', str(mount), '-plist', str(path)], 60)
            need(call.returncode == 0, 'p0-original-attach')
            device = self.stager.distribution_mount_data(call.stdout, call.stderr, call.returncode, mount)
            attached = True
            STATE['phase'] = 'mounted-inputs'
            mounted = self.fresh_book()
            directory = self.quota.call(mounted, 'directory', mount)
            def mounted_post():
                self.point(); mounted.check()
                held = os.fstat(directory['fd'])
                fs = self.host.filesystem(directory['fd'])
                mount_data(held, os.fstat(self.parent['fd']), fs, os.fstatvfs(directory['fd']).f_flag, mount, device)
                need(identity(os.stat(mount.name, dir_fd=self.parent['fd'], follow_symlinks=False)) == identity(held), 'p0-mounted-named-original')
                return fs
            facts = mounted_post()
            need(set(os.listdir(directory['fd'])) == {'Install.pkg', 'producer.json', 'producer.sig'}, 'p0-mounted-roster')
            originals = {}
            for key in ('package', 'descriptor', 'signature'):
                selected = row[key]; name = selected['name']
                info = os.stat(name, dir_fd=directory['fd'], follow_symlinks=False)
                need(info.st_uid in (0, os.getuid()) and info.st_gid in (0, os.getgid()), 'p0-mounted-owner')
                entry, body = self.quota.call(mounted, 'file', mount / name, selected['bytes'], uid=info.st_uid, modes=(0o444,))
                need((len(body), sha(body)) == (selected['bytes'], selected['sha256']), 'p0-mounted-original-pin')
                originals[name] = (body, stat.S_IMODE(info.st_mode))
            result, inventory = self.data.mounted_data(originals, row, target, self.stager)
            need(mounted_post() == facts and set(os.listdir(directory['fd'])) == set(originals), 'p0-mounted-filesystem-post')
            for entry in mounted.entries:
                if entry['kind'] == 'file':
                    need(mounted.read(entry) == originals[entry['path'].name][0], 'p0-mounted-original-byte-post')
            return result, inventory
        except BaseException as error:
            primary = error
            raise
        finally:
            # Known attach/device is established before any package parser can
            # refuse. Unknown attach/close never authorizes fallback cleanup.
            if attached:
                STATE['phase'] = 'detach-finality'
                self.clock.finality = True
                closed = mounted is None or mounted.finish()
                if closed:
                    try:
                        self.point()
                        call = self.command('detach', ['/usr/bin/hdiutil', 'detach', device], 30)
                        need(call.returncode == 0, 'p0-original-detach')
                        restored = self.fresh_book()
                        leaf = self.quota.call(restored, 'directory', mount)
                        need(leaf['identity'] == before and os.listdir(leaf['fd']) == []
                             and not os.fstatvfs(leaf['fd']).f_flag & os.ST_RDONLY, 'p0-restored-original-placeholder')
                        restored.check(); need(restored.finish(), 'p0-restored-placeholder-close')
                        self.outer.check(); os.rmdir(mount.name, dir_fd=self.parent['fd'])
                        need(not os.path.lexists(mount), 'p0-placeholder-retirement')
                        detached = True
                    except BaseException:
                        if primary is None: raise
                        primary.add_note('p0-known-device-finality-failed')
                elif primary is None:
                    raise Refused('p0-mounted-close-unknown')
                else:
                    primary.add_note('p0-mounted-close-unknown')
                self.clock.finality = False
            if primary is None:
                need(attached and detached, 'p0-image-finality')

    def publish(self, name, body):
        need(name in PUBLIC_NAMES and name not in self.public and type(body) is bytes
             and self.output_bytes + len(body) <= OUTPUT_LIMIT - TERMINAL_LIMIT, 'p0-public-output-bound')
        self.output_bytes += len(body)
        self.quota.call(self.outer, 'publish', self.work / 'public' / name, body, mode=0o444)
        entry = self.outer.entries[-1]
        need(entry['kind'] == 'output' and entry['path'] == self.work / 'public' / name
             and entry['closed'] and entry['identity'][6] == len(body), 'p0-public-original-output')
        self.public[name] = entry['identity']

    def retire_private(self):
        self.point()
        # Every disposable file original is consumed before its named retirement.
        for book in self.quota.books:
            for entry in reversed(book.entries):
                if entry['kind'] != 'directory': book.close(entry)
        need(all(not book.errors for book in self.quota.books), 'p0-original-file-close')
        self.outer.check()
        public = self.outer.directories[self.work / 'public']
        need(set(self.public) == set(self.expected_public) and set(os.listdir(public['fd'])) == set(self.public), 'p0-public-output-roster')
        for name, before in self.public.items():
            need(identity(os.stat(name, dir_fd=public['fd'], follow_symlinks=False)) == before, 'p0-public-output-post')
        need(set(os.listdir(self.parent['fd'])) == set(self.private) | {'public'}, 'p0-owned-output-roster')
        for name, before in self.private.items():
            need(identity(os.stat(name, dir_fd=self.parent['fd'], follow_symlinks=False)) == before, 'p0-private-retirement-original')
        for name in self.private:
            os.unlink(name, dir_fd=self.parent['fd'])
        os.fsync(self.parent['fd']); self.outer.check()
        need(set(os.listdir(self.parent['fd'])) == {'public'}, 'p0-private-retirement-post')
        STATE['privateOutputsRetired'] = True


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
    # Only this SOURCE-authenticated passive class must precede its own book.
    relative = 'desktop/tools/macos_e2_native_fixture.py'
    size, expected = SOURCE_PINS[relative]
    fd = os.open(root / relative, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    primary = None
    try:
        before = identity(os.fstat(fd))
        need(stat.S_ISREG(before[2]) and before[3] == os.getuid() and before[5] == 1 and not before[2] & 0o022
             and before[6] == size, 'p0-bootstrap-original')
        body = os.pread(fd, size + 1, 0)
        need(len(body) == size and sha(body) == expected and identity(os.fstat(fd)) == before
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


def main():
    environment = os.environ
    raw_start = environment.get('MRK_P0_TASK_STARTED_NS', '')
    need(re.fullmatch(r'[1-9][0-9]{0,19}', raw_start), 'p0-original-start')
    clock = Deadline(started=int(raw_start))
    need(sys.platform == 'darwin' and platform.machine() == 'x86_64' and os.getuid() != 0 and os.getuid() == os.geteuid()
         and os.getgid() == os.getegid() and environment.get('RUNNER_OS') == 'macOS'
         and environment.get('RUNNER_ARCH') == 'X64' and environment.get('RUNNER_ENVIRONMENT') == 'github-hosted'
         and environment.get('GITHUB_REPOSITORY') == REPOSITORY and environment.get('GITHUB_REF') == ENROLLMENT_REF
         and environment.get('GITHUB_WORKFLOW_REF') == REPOSITORY + '/.github/workflows/desktop-macos-p0-readonly-enrollment.yml@' + ENROLLMENT_REF
         and environment.get('GITHUB_SHA') == environment.get('GITHUB_WORKFLOW_SHA')
         and re.fullmatch(r'[0-9a-f]{40}', environment.get('GITHUB_SHA', ''))
         and re.fullmatch(r'[1-9][0-9]{0,19}', environment.get('GITHUB_RUN_ID', ''))
         and re.fullmatch(r'[1-9][0-9]{0,19}', environment.get('GITHUB_RUN_ATTEMPT', '')), 'p0-host-context')
    root = Path(__file__).absolute().parents[2]
    need(str(root) == environment.get('GITHUB_WORKSPACE') and str(root) == os.path.normpath(root)
         and environment.get('RUNNER_TEMP') == '/Users/runner/work/_temp', 'p0-host-source-route')
    work = Path(environment['RUNNER_TEMP']) / ('mrk-p0-readonly-' + environment['GITHUB_RUN_ID'] + '-' + environment['GITHUB_RUN_ATTEMPT'])
    # One fixed exclusive task root. Existing paths/collisions are never removed.
    os.mkdir(work, 0o700)
    quota = OriginalQuota()
    quota.reserve(1)  # Before opening the SOURCE-authenticated bootstrap original.
    session, primary = None, None
    try:
        session = Enrollment(root, work, clock, bootstrap_originals(root), quota=quota)
        STATE['phase'] = 'source'
        head = session.source('.git/HEAD', 64)
        need(head == (environment['GITHUB_SHA'] + '\n').encode('ascii'), 'p0-detached-source')
        expected_size, expected_sha = environment.get('MRK_P0_NATIVE_BYTES', ''), environment.get('MRK_P0_NATIVE_SHA256', '')
        need(re.fullmatch(r'[1-9][0-9]{0,5}', expected_size) and 0 < int(expected_size) <= SOURCE_LIMIT
             and re.fullmatch(r'[0-9a-f]{64}', expected_sha), 'p0-initial-source-binding')
        session.script = session.source('desktop/tools/macos_p0_readonly_native.py', int(expected_size), expected_sha)
        need(len(session.script) == int(expected_size), 'p0-initial-source-binding')
        session.source('.github/workflows/desktop-macos-p0-readonly-enrollment.yml', 16384)
        modules = {}
        for relative, (size, digest) in SOURCE_PINS.items():
            body = session.source(relative, size, digest)
            if relative.startswith('desktop/tools/') and relative.endswith('.py'):
                name = Path(relative).name
                if name == 'macos_e2_native_fixture.py': continue
                modules[name] = load_module('_mrk_p0_' + name[:-3], root / relative, body)
        session.data = modules['macos_p0_readonly_enrollment.py']
        session.stager = modules['stage_macos_installed.py']
        public = modules['macos_public_verification_evidence.py']
        update = modules['macos_update_verification.py']
        STATE['phase'] = 'qualification-anchors'
        document = decode(session.source(session.data.ANCHORS, 65536))
        selected_rows = qualified_rows_data(document, session.data, session.stager)
        selected_targets = tuple(target for target, _ in selected_rows)
        rows = [row for _, row in selected_rows]
        session.expected_public = tuple(name for target in selected_targets for name in
            (('arm64' if target == TARGETS[0] else 'intel') + '-installation-inventory.json',
             ('arm64' if target == TARGETS[0] else 'intel') + '-enrollment.json')) + ('enrollment-native.json',)
        # Exact owner loader and source pins, not an alternate process engine.
        aqua = modules['macos_aqua_qualification.py']
        session.owner = aqua.load_owner(root)
        session.host = modules['macos_xcode_host_preparation.py'].DarwinAPI(clock, target=TARGETS[1])
        session.host.waitable_sigchld()
        session.python = os.path.realpath(sys.executable)
        for tool in (session.python, '/usr/bin/hdiutil', '/usr/bin/vm_stat'):
            entry, _ = session.quota.call(session.outer, 'file', Path(tool), 64 << 20, uid=0, modes=(0o555, 0o755))
            need(entry['identity'][6] > 0, 'p0-tool-original')
        ca = ssl.get_default_verify_paths().cafile
        need(type(ca) is str and os.path.isabs(ca), 'p0-stock-ca-unavailable')
        session.ca_path = os.path.realpath(ca)
        entry, ca_body = session.quota.call(session.outer, 'file', Path(session.ca_path), 2 << 20, uid=0, modes=(0o444, 0o644))
        session.ca_sha = sha(ca_body)
        session.token = environment.get('GITHUB_TOKEN')
        request_headers(authenticated=True, token=session.token)
        session.environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}
        os.mkdir('public', 0o700, dir_fd=session.parent['fd'])
        source_bytes = sum(len(body) for _, body in session.sources) + len(ca_body)
        STATE['phase'] = 'resource-admission'
        memory_call = session.command('memory', ['/usr/bin/vm_stat'], 10)
        page_size, physical_bytes = host_memory_data(session.host, clock)
        memory = memory_data(memory_call.stdout, memory_call.stderr, memory_call.returncode,
                             page_size=page_size, physical_bytes=physical_bytes)
        memory['observedMonotonicNs'] = clock.check()
        quotes = [resource_quote_data(row, source_bytes, update) for row in rows]
        disk = os.fstatvfs(session.parent['fd'])
        resource_admission = resource_admission_data(memory, disk.f_bavail * disk.f_frsize, quotes)
        for target, row in selected_rows:
            session.point()
            STATE['phase'] = 'qualification-acquisition'
            qualified = session.acquire(row, target, 'qualification')['public-verification-evidence.json']
            STATE['phase'] = 'qualification-correspondence'
            context, deliveries = session.data.qualification_data(qualified, row, target, session.stager, public)
            STATE['phase'] = 'carrier-acquisition'
            artifact = session.acquire(row, target, 'carrier')
            STATE['phase'] = 'carrier-correspondence'
            image = session.data.artifact_data(artifact, row, context, deliveries, session.stager, public)
            STATE['phase'] = 'image-copy'
            result, inventory = session.inspect_image(image, row, target)
            result = dict(result)
            result.pop('inventoryDocument')  # Retain exact original bytes once, below.
            result.update(hostArchitecture='x86_64', hostMacOSVersion=session.host.version,
                          enrollmentSource=environment['GITHUB_SHA'], enrollmentRunId=environment['GITHUB_RUN_ID'],
                          enrollmentRunAttempt=environment['GITHUB_RUN_ATTEMPT'], originalMountDetached=True)
            label = 'arm64' if target == TARGETS[0] else 'intel'
            STATE['phase'] = 'public-inventory'
            session.publish(label + '-installation-inventory.json', inventory)
            session.publish(label + '-enrollment.json', canonical(result))
            session.results.append(result)
            del result, inventory, image, artifact, qualified
        session.point()
        summary = {'schemaVersion': 1, 'kind': 'mrk-p0-readonly-native-enrollment-v1',
                   'source': environment['GITHUB_SHA'], 'workflowSource': environment['GITHUB_WORKFLOW_SHA'],
                   'runId': environment['GITHUB_RUN_ID'], 'runAttempt': environment['GITHUB_RUN_ATTEMPT'],
                   'workflow': '.github/workflows/desktop-macos-p0-readonly-enrollment.yml',
                   'hostArchitecture': 'x86_64', 'targets': [v['target'] for v in session.results],
                   'combinedTwoTargetEnrollmentAccepted': len(selected_targets) == 2,
                   'memoryObservation': memory, 'resourceQuotes': quotes, 'resourceAdmission': resource_admission, 'originalCalls': session.calls,
                   'originalAdmissions': session.quota.reserved, 'installOrPayloadExecuted': False,
                   'storeMutationPerformed': False, 'signingCredentialsAccessed': False,
                   'updateActivated': False, 'productReady': False}
        STATE['phase'] = 'public-summary'
        session.publish('enrollment-native.json', canonical(summary))
        STATE['phase'] = 'private-finality'
        session.clock.finality = True
        session.retire_private()
        for entry, body in session.sources:
            # Source files were known closed by retire_private; exact byte POST
            # was already admitted by every original command/phase point.
            need(entry['closed'], 'p0-source-close')
        need(session.quota.finish(), 'p0-original-final-closes')
        session.clock.check()
        STATE['workloadsKnownSettled'] = all(row['returned'] and row['capturesSettled'] for row in session.calls)
        need(STATE['workloadsKnownSettled'], 'p0-terminal-workloads')
        STATE['phase'] = 'complete'
        return {'schemaVersion': 1, 'source': environment['GITHUB_SHA'], 'nativeEnrollmentAccepted': True,
                'originalClosesKnown': True, 'privateOutputsRetired': True,
                'publicOutputsRetained': True, 'workloadsKnownSettled': True,
                'targets': list(selected_targets), 'combinedTwoTargetEnrollmentAccepted': len(selected_targets) == 2,
                'productReady': False}
    except BaseException as error:
        primary = error
        raise
    finally:
        # Consume only our original books. Unknown workloads/close failures keep
        # all unretired task files; no guessed detach, broad delete or service stop.
        try:
            settled = quota.finish()
        except BaseException:
            settled = False
            if primary is None: raise
            primary.add_note('p0-original-final-closes')
        STATE['originalClosesKnown'] = settled
        STATE['workloadsKnownSettled'] = session is not None and bool(session.calls) and all(row['returned'] and row['capturesSettled'] for row in session.calls)
        if not settled:
            if primary is None: raise Refused('p0-original-final-closes')
            primary.add_note('p0-original-final-closes')













FINITE_REASONS = ('collector-public-compressed-crc', 'collector-public-compressed-eof', 'collector-public-compressed-progress', 'collector-public-compressed-short', 'collector-public-compressed-span', 'collector-public-compressed-tail', 'collector-public-compression', 'collector-public-stored-size', 'p0-acquisition-closed-report', 'p0-acquisition-original', 'p0-acquisition-original-post', 'p0-acquisition-parent-original', 'p0-artifact-api-redirect', 'p0-artifact-bound', 'p0-artifact-digest', 'p0-artifact-original', 'p0-artifact-post', 'p0-artifact-readback', 'p0-artifact-redirect', 'p0-artifact-response', 'p0-artifact-response-bytes', 'p0-artifact-write', 'p0-bootstrap-close-unknown', 'p0-bootstrap-original', 'p0-bootstrap-source', 'p0-borrowed-ancestor-admission', 'p0-borrowed-parent-custody', 'p0-ca-original', 'p0-ca-pin', 'p0-child-admission', 'p0-child-close-unknown', 'p0-child-original-request-bound', 'p0-child-post-deadline', 'p0-child-request', 'p0-child-source-bound', 'p0-child-work-original', 'p0-command-admission-deadline', 'p0-command-role', 'p0-detached-source', 'p0-empty-original-placeholder', 'p0-fixed-command', 'p0-fresh-book-shape', 'p0-host-context', 'p0-host-source-route', 'p0-image-copy-admission', 'p0-image-copy-close', 'p0-image-copy-original-quote', 'p0-image-copy-readback', 'p0-image-copy-write', 'p0-image-finality', 'p0-image-published-original', 'p0-initial-source-binding', 'p0-json-duplicate', 'p0-json-graph', 'p0-json-number', 'p0-json-scalar', 'p0-json-size', 'p0-json-string', 'p0-json-width', 'p0-memory-bound', 'p0-memory-counter', 'p0-memory-header', 'p0-memory-host-original', 'p0-memory-lines', 'p0-memory-original', 'p0-memory-page-size', 'p0-metadata-artifact', 'p0-metadata-bound', 'p0-metadata-bytes', 'p0-metadata-job', 'p0-metadata-response', 'p0-metadata-run', 'p0-metadata-shape', 'p0-mounted-close-unknown', 'p0-mounted-filesystem-post', 'p0-mounted-named-original', 'p0-mounted-original-byte-post', 'p0-mounted-original-pin', 'p0-mounted-owner', 'p0-mounted-roster', 'p0-original-admission', 'p0-original-attach', 'p0-original-command', 'p0-original-detach', 'p0-original-file-close', 'p0-original-final-closes', 'p0-original-method', 'p0-original-path', 'p0-original-quote-correspondence', 'p0-original-start', 'p0-owned-output-roster', 'p0-placeholder-close', 'p0-placeholder-retirement', 'p0-private-retirement-original', 'p0-private-retirement-post', 'p0-public-original-output', 'p0-public-output-bound', 'p0-public-output-post', 'p0-public-output-roster', 'p0-qualification-anchors-unconfigured', 'p0-readonly-mount', 'p0-resource-reserve', 'p0-resource-shape', 'p0-response-headers', 'p0-restored-original-placeholder', 'p0-restored-placeholder-close', 'p0-service-token', 'p0-source-close', 'p0-source-module-collision', 'p0-source-pin', 'p0-stock-ca-unavailable', 'p0-task-deadline', 'p0-terminal-output-bound', 'p0-terminal-workloads', 'p0-tls-policy', 'p0-tool-original', 'p0-zip-central', 'p0-zip-descriptor', 'p0-zip-local', 'p0-zip-local-size', 'p0-zip-member', 'p0-zip-member-original', 'p0-zip-original', 'p0-zip-roster', 'p0-zip-unaccounted-bytes')


def failure_data(error):
    # Whitelisted literal reasons only: never exception formatting/paths/URLs.
    reason = error.args[0] if type(error) is Refused and len(error.args) == 1 and type(error.args[0]) is str and error.args[0] in FINITE_REASONS else None
    phases = ('admission', 'source', 'qualification-anchors', 'resource-admission', 'qualification-acquisition',
              'qualification-correspondence', 'carrier-acquisition', 'carrier-correspondence', 'image-copy',
              'attach', 'mounted-inputs', 'detach-finality', 'public-inventory', 'public-summary', 'private-finality', 'complete')
    roles = ('memory', 'acquire-qualification', 'acquire-carrier', 'attach', 'detach')
    return {'schemaVersion': 1, 'nativeEnrollmentAccepted': False,
            'failureClass': 'Refused' if type(error) is Refused else 'OriginalOperationFailed',
            'condition': reason, 'phase': STATE.get('phase') if STATE.get('phase') in phases else 'unknown',
            'lastRole': STATE.get('lastRole') if STATE.get('lastRole') in roles else None,
            'originalClosesKnown': STATE.get('originalClosesKnown') is True,
            'privateOutputsRetired': STATE.get('privateOutputsRetired') is True,
            'workloadsKnownSettled': STATE.get('workloadsKnownSettled') is True, 'productReady': False}


if __name__ == '__main__':
    try:
        need(sys.argv[1:] in ([], ['acquire']), 'p0-fixed-command')
        result = acquisition_main() if sys.argv[1:] else main()
        output = canonical(result)
        need(len(output) <= TERMINAL_LIMIT, 'p0-terminal-output-bound')
        print(output.decode('ascii'))
    except BaseException as error:
        output = canonical(failure_data(error))
        # Only this small terminal is retained on failure; never inventories.
        if len(output) <= TERMINAL_LIMIT: print(output.decode('ascii'))
        raise SystemExit(1) from None
