"""Closed hosted build-part transport. No native signer or installed authority.

Only completed SOURCE-selected outputs cross runners. Each destination is a
fresh object; original receipts remain bytes, never rewritten custody facts.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import stat
import struct
import subprocess
import sys
import time
import zipfile
import zlib


def load(name):
    spec = importlib.util.spec_from_file_location('mrk_parts_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load('macos_candidate_parts')
S = load('stage_macos_installed')
need = P.need
# Explicit output namespaces, not the whole task root, targets, home or cache.
ROSTER = {
    'prepare': ('work/runtime', 'work/runtime-binding.json', 'work/signed-python-capsule/python-signed-receipt.json',
                'work/signed-android-transport', 'work/github-seal-capsule'),
    'resident': ('work/libmrk_resident_image.dylib', 'work/mrk-macos-entry', 'work/mobile-release-kit-desktop',
                 'work/mrk-android-register', 'work/android-helper-prepare.json'),
    'vault': ('work/vault-helper-target/aarch64-apple-darwin/release/mrk-vault-keychain',
              'work/vault-helper-build.jsonl', 'work/vault-helper-build.status', 'work/vault-helper-signing.json',
              'work/android-helper-sign-vault-helper.json'),
    'frontend': ('dist',),
    'observer': ('work/observer-build.jsonl', 'work/observer-build.status',
                 'work/cargo-target/aarch64-apple-darwin/debug/deps'),
    'remover': ('work/remover-target/aarch64-apple-darwin/release/mrk-macos-remove',
                'work/remover-build.jsonl', 'work/remover-build.status'),
    'cli': ('work/installed-cli-target/aarch64-apple-darwin/release/mrk',
            'work/installed-cli-build.jsonl', 'work/installed-cli-build.status'),
    'sign-remover': ('work/remover-target/aarch64-apple-darwin/release/mrk-macos-remove',
                     'work/android-helper-sign-remover.json'),
    'sign-cli': ('work/installed-cli-target/aarch64-apple-darwin/release/mrk',
                 'work/android-helper-sign-installed-cli.json'),
    'assemble': ('work/app', 'work/app-result.json', 'work/android-helper-verify-before.json',
                 'work/android-helper-sign-desktop-payload.json', 'work/android-helper-sign-root-app.json',
                 'work/android-helper-verify-after.json'),
    'notarize-payload': ('work/input', 'work/input-result.json', 'work/android-helper-notarize-payload.json'),
    'installer': ('work/cargo-target/aarch64-apple-darwin/release/mrk-macos-install',),
    'scripts-package': ('work/scripts', 'work/scripts-result.json', 'work/MobileReleaseKit-original.pkg',
                        'work/package-parts', 'work/package-unsigned', 'work/package-prepare.json',
                        'work/package-tar.status', 'work/package-xar.status',
                        'work/android-helper-sign-root-installer.json'),
}
OPTIONAL = frozenset({'work/github-seal-capsule'})
# The one original Cargo alias may have two links, which must be both known.
ALIASES = {
    'work/vault-helper-target/aarch64-apple-darwin/release/mrk-vault-keychain': 'mrk_vault_keychain-',
    'work/remover-target/aarch64-apple-darwin/release/mrk-macos-remove': 'mrk_macos_remove-',
    'work/installed-cli-target/aarch64-apple-darwin/release/mrk': 'mrk-',
    'work/cargo-target/aarch64-apple-darwin/release/mrk-macos-install': 'mrk_macos_install-',
}
RECEIPTS = {
    'resident': ('prepare',), 'vault': ('sign-vault-helper',),
    'sign-remover': ('sign-remover',), 'sign-cli': ('sign-installed-cli',),
    'assemble': ('verify-before', 'sign-desktop-payload', 'sign-root-app', 'verify-after'),
    'notarize-payload': ('notarize-payload',), 'scripts-package': ('sign-root-installer',),
}


def sig(info):
    return S.signature(info)


@contextlib.contextmanager
def original(path, limit, *, alias_prefix=None):
    with S.parent(path) as (parent, name):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_gid == os.getgid()
             and 0 <= before.st_size <= limit and getattr(before, 'st_flags', 0) == 0
             and (before.st_nlink == 1 or alias_prefix and before.st_nlink == 2), 'part-original-policy')
        if before.st_nlink == 2:
            deps = path.parent / 'deps'
            names = os.listdir(deps)
            need(len(names) <= 8192, 'part-cargo-alias-count')
            matches = [n for n in names if re.fullmatch(re.escape(alias_prefix) + '[0-9a-f]+', n)
                       and sig(os.stat(deps / n, follow_symlinks=False)) == sig(before)]
            need(len(matches) == 1, 'part-cargo-original-alias')
        fd = os.open(name, S.READ_FLAGS, dir_fd=parent)
        try:
            need(sig(os.fstat(fd)) == sig(before), 'part-original-open')
            S.no_xattrs(fd)
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                yield stream, before
            need(sig(os.fstat(fd)) == sig(before) == sig(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                 'part-original-post')
            S.no_xattrs(fd)
        finally:
            S.close_once(fd)


def read(path, maximum):
    with original(path, maximum) as (stream, info):
        body = stream.read(maximum + 1)
        need(len(body) == info.st_size, 'part-original-eof')
    return body


def exclusive(path, callback, mode=0o600):
    with S.parent(path) as (parent, name):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, 'w+b', closefd=False) as stream:
                result = callback(stream)
                stream.flush()
                os.fchmod(fd, mode)
                os.fsync(fd)
            before = os.fstat(fd)
            need(before.st_nlink == 1 and sig(before) == sig(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                 'part-writer-name-post')
            S.no_xattrs(fd)
            os.fsync(parent)
        finally:
            S.close_once(fd)
    return result


def write(path, body, mode=0o600):
    exclusive(path, lambda stream: stream.write(body), mode)
    need(read(path, len(body)) == body, 'part-writer-reader-correspondence')


def destination(name, work, workspace):
    P.path_data(name + '/placeholder' if name == 'dist' else name)
    return workspace / 'desktop/dist' / name[5:] if name.startswith('dist/') else (
        workspace / 'desktop/dist' if name == 'dist' else work / name[5:])


def permitted(part, name, observer_name=None):
    P.part_name(part)
    need(part in ROSTER, 'part-export-purpose')
    if part == 'observer' and name.startswith(ROSTER[part][2] + '/'):
        return name == ROSTER[part][2] + '/' + observer_name
    return any(name == root or name.startswith(root + '/') for root in ROSTER[part])


def observer_name(work):
    body = read(work / 'observer-build.jsonl', 8 * 1024 * 1024)
    rows = [json.loads(line) for line in body.splitlines()]
    need([r.get('success') for r in rows if r.get('reason') == 'build-finished'] == [True], 'part-observer-zero')
    rows = [r for r in rows if r.get('reason') == 'compiler-artifact'
            and r.get('target', {}).get('name') == 'installed-shell-observation' and r.get('executable')]
    need(len(rows) == 1 and rows[0]['target'].get('kind') == ['test'] and rows[0].get('profile', {}).get('test') is True,
         'part-observer-cargo')
    path = Path(rows[0]['executable'])
    need(path.parent == work / 'cargo-target' / P.TARGET / 'debug/deps'
         and re.fullmatch('installed_shell_observation-[0-9a-f]+', path.name), 'part-observer-path')
    return path.name


def selected_files(part, work, workspace):
    files, directories = {}, {}
    observer = observer_name(work) if part == 'observer' else None
    def visit(name):
        path = destination(name, work, workspace)
        info = path.lstat()
        need(info.st_uid == os.getuid() and info.st_gid == os.getgid() and getattr(info, 'st_flags', 0) == 0,
             'part-output-owner-flags')
        if stat.S_ISDIR(info.st_mode):
            with S.parent(path) as (parent, leaf):
                fd = os.open(leaf, S.READ_FLAGS | os.O_DIRECTORY, dir_fd=parent)
                try:
                    S.no_xattrs(fd)
                    names = sorted(os.listdir(fd))
                    need(len(names) <= P.MAX_MEMBERS, 'part-directory-bound')
                    directories[name] = stat.S_IMODE(info.st_mode)
                    for child in names:
                        visit(name + '/' + child)
                    need(names == sorted(os.listdir(fd)) and sig(os.fstat(fd)) == sig(info)
                         == sig(os.stat(leaf, dir_fd=parent, follow_symlinks=False)), 'part-directory-post')
                finally: S.close_once(fd)
        else:
            need(permitted(part, name, observer), 'part-source-roster')
            with original(path, P.MEMBER_LIMIT, alias_prefix=ALIASES.get(name)) as (stream, before):
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            files[name] = {'path': name, 'bytes': before.st_size, 'mode': stat.S_IMODE(before.st_mode), 'sha256': digest}
        need(len(files) + len(directories) <= P.MAX_MEMBERS, 'part-total-roster-bound')
    for name in ROSTER[part]:
        path = destination(name, work, workspace)
        if name in OPTIONAL and not os.path.lexists(path): continue
        if part == 'observer' and name == ROSTER[part][2]:
            visit(name + '/' + observer)
        else: visit(name)
    return files, directories


def receipt_checks(part, work, origin):
    for phase in RECEIPTS.get(part, ()):
        row = json.loads(read(work / ('android-helper-' + phase + '.json'), 16384))
        need(row.get('phase') == phase and row.get('source') == row.get('workflowSource') == origin['source']
             and row.get('runId') == origin['runId'] and row.get('runAttempt') == origin['runAttempt']
             and row.get('target') == P.TARGET and row.get('passed') is True
             and row.get('targetRetired') is True and row.get('originalClosesKnown') is True,
             'part-original-owner-completion')
    for prefix in {'observer': ('observer',), 'remover': ('remover',), 'cli': ('installed-cli',),
                   'vault': ('vault-helper',), 'scripts-package': ('package-tar', 'package-xar')}.get(part, ()):
        need(read(work / (prefix + ('.status' if prefix.startswith('package-') else '-build.status')), 8) == b'0\n',
             'part-original-caller-zero')


def encode_archive(path, manifest, files, work, workspace):
    body = P.canonical(P.manifest_data(manifest))
    def writer(stream):
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
            archive.writestr('PART.json', body)
            for name, row in sorted(files.items()):
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | row['mode']) << 16
                with original(destination(name, work, workspace), P.MEMBER_LIMIT,
                              alias_prefix=ALIASES.get(name)) as (source, before):
                    need(before.st_size == row['bytes'] and stat.S_IMODE(before.st_mode) == row['mode'], 'part-export-changed')
                    digest, count = hashlib.sha256(), 0
                    with archive.open(info, 'w') as output:
                        while block := source.read(65536):
                            count += len(block); need(count <= row['bytes'], 'part-export-grew')
                            digest.update(block); output.write(block)
                    need(count == row['bytes'] and digest.hexdigest() == row['sha256'], 'part-export-post-hash')
    exclusive(path, writer, 0o444)


def archive_entries(stream, length, *, maximum_members, service_descriptor=False):
    need(22 <= length <= P.TOTAL_LIMIT + P.MANIFEST_LIMIT + 16 * 1024 * 1024, 'part-archive-bound')
    stream.seek(length - 22)
    footer = struct.unpack('<4s4H2LH', stream.read(22))
    need(footer[0] == b'PK\x05\x06' and footer[1:3] == (0, 0) and footer[3] == footer[4]
         and 1 <= footer[3] <= maximum_members and footer[7] == 0
         and 0 < footer[5] <= 16 * 1024 * 1024 and footer[6] + footer[5] == length - 22,
         'part-archive-footer')
    if length >= 42:
        stream.seek(length - 42); need(stream.read(4) != b'PK\x06\x07', 'part-zip64-refused')
    stream.seek(0)
    with zipfile.ZipFile(stream) as archive:
        infos = archive.infolist()
    need(len(infos) == footer[3] and len({i.filename for i in infos}) == len(infos), 'part-zip-roster')
    need(sum(46 + len(i.filename.encode('utf-8' if i.flag_bits & 0x800 else 'ascii'))
             + len(i.extra) + len(i.comment) for i in infos) == footer[5], 'part-central-exact-span')
    offset, entries = 0, {}
    for info in infos:
        descriptor = service_descriptor and info.flag_bits in (8, 0x808)
        need(info.header_offset == offset and info.compress_type in (0, 8)
             and (info.flag_bits in (0, 0x800) or descriptor) and not info.extra and not info.comment
             and info.volume == 0 and not info.is_dir() and not stat.S_ISLNK(info.external_attr >> 16), 'part-zip-member')
        stream.seek(offset)
        header = struct.unpack('<4s5H3L2H', stream.read(30))
        encoded = info.filename.encode('utf-8' if info.flag_bits & 0x800 else 'ascii')
        need(header[0] == b'PK\x03\x04' and header[2] == info.flag_bits and header[3] == info.compress_type
             and header[6:9] == ((0, 0, 0) if descriptor else (info.CRC, info.compress_size, info.file_size))
             and header[9:] == (len(encoded), 0) and stream.read(len(encoded)) == encoded,
             'part-local-central-correspondence')
        start = offset + 30 + len(encoded)
        offset = start + info.compress_size
        if descriptor:
            # The actual GitHub wrapper streams one signed 16-byte descriptor.
            # Match every field to the central original; never infer sizes/CRC
            # from an empty local header or scan for a payload signature.
            need(offset + 16 <= footer[6], 'part-service-descriptor-span')
            stream.seek(offset)
            need(stream.read(16) == struct.pack('<4s3L', b'PK\x07\x08', info.CRC,
                                              info.compress_size, info.file_size),
                 'part-service-descriptor-correspondence')
            offset += 16
        need(offset <= footer[6], 'part-zip-member-span')
        entries[info.filename] = (info, start)
    need(offset == footer[6], 'part-zip-span-roster')
    return entries


def stream_member(stream, entry, maximum, output):
    info, start = entry
    need(0 <= info.file_size <= maximum and 0 <= info.compress_size <= P.TOTAL_LIMIT,
         'part-member-allocation')
    stored = info.compress_type == 0
    need(not stored or info.compress_size == info.file_size, 'part-stored-length')
    stream.seek(start)
    remaining, count, crc, digest = info.compress_size, 0, 0, hashlib.sha256()
    inflater = None if stored else zlib.decompressobj(-15)
    while remaining:
        block = stream.read(min(65536, remaining))
        need(block, 'part-compressed-short'); remaining -= len(block)
        while True:
            data = block if stored else inflater.decompress(block, 65536)
            count += len(data); need(count <= info.file_size, 'part-expanded-overflow')
            digest.update(data); crc = zlib.crc32(data, crc); output.write(data)
            if stored: break
            need(not inflater.unused_data, 'part-codec-tail')
            block = inflater.unconsumed_tail
            if inflater.eof:
                need(not block and remaining == 0, 'part-codec-span'); break
            if not block and len(data) < 65536: break
    need(stored or inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail, 'part-codec-eof')
    need(count == info.file_size and crc & 0xffffffff == info.CRC, 'part-codec-crc')
    return digest.hexdigest()


def archive_manifest(path):
    import io
    with original(path, P.TOTAL_LIMIT + P.MANIFEST_LIMIT + 16 * 1024 * 1024) as (stream, info):
        entries = archive_entries(stream, info.st_size, maximum_members=P.MAX_MEMBERS + 1)
        need('PART.json' in entries, 'part-manifest-required')
        out = io.BytesIO(); stream_member(stream, entries['PART.json'], P.MANIFEST_LIMIT, out)
        manifest = P.manifest_data(P.decode(out.getvalue()))
        need(set(entries) == {'PART.json'} | {r['path'] for r in manifest['members']}, 'part-archive-exact-roster')
        observer = next((Path(r['path']).name for r in manifest['members']
                         if r['path'].startswith('work/cargo-target/' + P.TARGET + '/debug/deps/')), None)
        need(all(permitted(manifest['part'], r['path'], observer) for r in manifest['members']), 'part-import-source-roster')
        need(all(permitted(manifest['part'], r['path'], observer) for r in manifest['directories']), 'part-import-directory-roster')
        need(all(entries[r['path']][0].compress_type == 0 and entries[r['path']][0].file_size == r['bytes']
                 and entries[r['path']][0].external_attr >> 16 == stat.S_IFREG | r['mode']
                 for r in manifest['members']), 'part-archive-member-metadata')
    return manifest


def project_archive(path, manifest, work, workspace, selected):
    # The selected final writer for each path is chosen by dependency order.
    # Unsigned and signed versions are never overlaid or adopted by hash alone.
    with original(path, P.TOTAL_LIMIT + P.MANIFEST_LIMIT + 16 * 1024 * 1024) as (stream, info):
        entries = archive_entries(stream, info.st_size, maximum_members=P.MAX_MEMBERS + 1)
        for row in manifest['members']:
            if selected[row['path']] != manifest['part']:
                class Discard:
                    def write(self, body): return len(body)
                need(stream_member(stream, entries[row['path']], row['bytes'], Discard()) == row['sha256'],
                     'part-unselected-original-sha256')
                continue
            target = destination(row['path'], work, workspace)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            digest = exclusive(target, lambda out: stream_member(stream, entries[row['path']], row['bytes'], out), row['mode'])
            need(digest == row['sha256'], 'part-fresh-copy-sha256')
            with original(target, row['bytes']) as (copied, after):
                need(after.st_size == row['bytes'] and stat.S_IMODE(after.st_mode) == row['mode']
                     and hashlib.file_digest(copied, 'sha256').hexdigest() == row['sha256'], 'part-fresh-copy-readback')


def api_bytes(route, maximum, sink=None):
    need(route.startswith('repos/' + P.REPOSITORY + '/') and '\n' not in route, 'part-api-route')
    child = subprocess.Popen(['gh', 'api', route], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    result, count, end = bytearray(), 0, time.monotonic() + 300
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while True:
                need(time.monotonic() < end, 'part-api-deadline')
                if not selector.select(min(1, max(0, end - time.monotonic()))): continue
                block = os.read(child.stdout.fileno(), 65536)
                if not block: break
                count += len(block); need(count <= maximum, 'part-api-original-bound')
                if sink is None: result.extend(block)
                else: sink.write(block)
        need(child.wait(timeout=max(1, end - time.monotonic())) == 0, 'part-api-original-return')
    finally:
        child.stdout.close()
        if child.poll() is None:
            child.kill(); child.wait(timeout=10)
    return bytes(result)


def api_json(route):
    return json.loads(api_bytes(route, 8 * 1024 * 1024))


def listing(route, key):
    rows = []
    for page in range(1, 11):
        row = api_json(route + ('&' if '?' in route else '?') + 'per_page=100&page=' + str(page))
        need(type(row.get(key)) is list and type(row.get('total_count')) is int
             and row['total_count'] <= 1000, 'part-service-page-bound')
        rows.extend(row[key])
        if len(rows) == row['total_count']: return rows
        need(len(rows) < row['total_count'] and len(row[key]) == 100, 'part-service-page-completeness')
    raise ValueError('part-service-page-limit')


def host():
    env = os.environ
    need(sys.platform == 'darwin' and os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid()
         and os.uname().machine == 'arm64', 'part-host')
    required = dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='macOS', RUNNER_ARCH='ARM64',
        GITHUB_EVENT_NAME='push', GITHUB_REPOSITORY=P.REPOSITORY, GITHUB_REF='refs/heads/' + P.BRANCH,
        GITHUB_WORKSPACE='/Users/runner/work/mobile-release-kit/mobile-release-kit',
        GITHUB_WORKFLOW_REF=P.REPOSITORY + '/' + P.WORKFLOW + '@refs/heads/' + P.BRANCH)
    need(all(env.get(k) == v for k, v in required.items()) and env.get('GITHUB_SHA') == env.get('GITHUB_WORKFLOW_SHA'),
         'part-host-source-route')
    work, workspace = Path(env['MRK_MACOS_WORK']), Path(env['GITHUB_WORKSPACE'])
    need(work.parent == Path('/Users/runner/work/_temp') and re.fullmatch(r'mrk-macos-installed\.[A-Za-z0-9]{8}', work.name),
         'part-work-route')
    return work, workspace


def current(part, work):
    source = json.loads(read(work / 'source-inventory.json', 2 * 1024 * 1024))
    origin = dict(source=os.environ['GITHUB_SHA'], tree=source['tree'], target=P.TARGET,
        runId=os.environ['GITHUB_RUN_ID'], runAttempt=os.environ['GITHUB_RUN_ATTEMPT'], jobId='1',
        nativeScope=os.environ['MRK_MACOS_NATIVE_SCOPE'], hostProfile=os.environ['MRK_MACOS_RUNNER'])
    P.origin_data(origin)
    jobs = listing('repos/' + P.REPOSITORY + '/actions/runs/' + origin['runId'] +
                   '/attempts/' + origin['runAttempt'] + '/jobs', 'jobs')
    rows = [j for j in jobs if j.get('name') == P.job_name(part, origin) and j.get('status') == 'in_progress']
    need(len(rows) == 1 and rows[0].get('head_sha') == origin['source'], 'part-current-actual-job')
    origin['jobId'] = str(rows[0]['id'])
    return origin


def resource(work, amount):
    observed = os.statvfs(work)
    need(type(amount) is int and 0 <= amount <= 4 * P.TOTAL_LIMIT
         and observed.f_bavail * observed.f_frsize >= amount + 32 * 1024 * 1024, 'part-current-disk-quote')


def freeze(part, work, workspace):
    origin = current(part, work)
    receipt_checks(part, work, origin)
    files, directories = selected_files(part, work, workspace)
    dependencies = P.decode(read(work / 'part-dependencies.json', P.MANIFEST_LIMIT)) if part != 'prepare' else []
    manifest = dict(schemaVersion=1, scope=P.SCOPE, part=part, origin=origin, workName=work.name,
        dependencies=dependencies, members=[files[name] for name in sorted(files)],
        directories=[dict(path=name, mode=mode) for name, mode in sorted(directories.items())],
        originalCallerZero=True, originalReadsClosed=True, nativeAuthority=False, installed=False, productReady=False)
    P.manifest_data(manifest)
    resource(work, sum(row['bytes'] for row in files.values()) + P.MANIFEST_LIMIT)
    path = work / 'PART.zip'
    encode_archive(path, manifest, files, work, workspace)
    need(archive_manifest(path) == manifest, 'part-final-archive-readback')
    # Recheck the original producer roster after the completed archive closes.
    need(selected_files(part, work, workspace) == (files, directories), 'part-original-roster-post')
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='ascii') as out:
        out.write('artifact-name=' + P.artifact_name(part, origin) + '\narchive=' + str(path) + '\n')


def restore(part, work, workspace):
    origin = current(part, work)
    run = api_json('repos/' + P.REPOSITORY + '/actions/runs/' + origin['runId'])
    jobs = listing('repos/' + P.REPOSITORY + '/actions/runs/' + origin['runId'] + '/jobs?filter=all', 'jobs')
    artifacts = listing('repos/' + P.REPOSITORY + '/actions/runs/' + origin['runId'] + '/artifacts', 'artifacts')
    records, manifests, paths = {}, {}, {}
    staging = work / 'part-inputs'; staging.mkdir(mode=0o700)
    for prior in P.ancestors(part):
        candidates = []
        for job in jobs:
            if job.get('name') != P.job_name(prior, origin) or job.get('status') != 'completed' or job.get('conclusion') != 'success':
                continue
            prior_origin = dict(origin, jobId=str(job['id']), runAttempt=str(job['run_attempt']))
            found = [a for a in artifacts if a.get('name') == P.artifact_name(prior, prior_origin) and a.get('expired') is False]
            if len(found) == 1: candidates.append((job, found[0], prior_origin))
        # Copied jobs in later reruns have no artifact for that copied attempt.
        need(len(candidates) == 1, 'part-one-completed-original')
        job, artifact, prior_origin = candidates[0]
        P.service_metadata_data(run, job, artifact, prior, prior_origin)
        need(type(artifact.get('size_in_bytes')) is int and 22 <= artifact['size_in_bytes'] <= P.TOTAL_LIMIT,
             'part-actual-download-size')
        resource(work, artifact['size_in_bytes'] * 2 + P.MANIFEST_LIMIT)
        outer, inner = staging / (prior + '-service.zip'), staging / (prior + '.zip')
        exclusive(outer, lambda out: api_bytes('repos/' + P.REPOSITORY + '/actions/artifacts/' + str(artifact['id']) + '/zip',
                                              artifact['size_in_bytes'], out), 0o444)
        with original(outer, artifact['size_in_bytes']) as (stream, info):
            need(info.st_size == artifact['size_in_bytes'] and 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest()
                 == artifact.get('digest'), 'part-service-original-digest')
            entries = archive_entries(stream, info.st_size, maximum_members=1, service_descriptor=True)
            need(set(entries) == {'PART.zip'}, 'part-service-wrapper-roster')
            exclusive(inner, lambda out: stream_member(stream, entries['PART.zip'], P.TOTAL_LIMIT, out), 0o444)
        manifest = archive_manifest(inner)
        record = P.metadata_data(run, job, artifact, manifest)
        need(manifest['origin'] == prior_origin and manifest['workName'] == work.name
             and manifest['dependencies'] == [records[p] for p in P.ancestors(prior)], 'part-original-dependency-chain')
        records[prior], manifests[prior], paths[prior] = record, manifest, inner
    chosen, directory_modes = {}, {}
    for prior in P.ancestors(part):
        for row in manifests[prior]['members']: chosen[row['path']] = prior
        for row in manifests[prior]['directories']: directory_modes[row['path']] = row['mode']
    resource(work, sum(r['bytes'] for p in manifests for r in manifests[p]['members'] if chosen[r['path']] == p))
    for prior in P.ancestors(part): project_archive(paths[prior], manifests[prior], work, workspace, chosen)
    for name, mode in sorted(directory_modes.items(), reverse=True):
        target = destination(name, work, workspace)
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        with S.parent(target) as (parent, leaf):
            fd = os.open(leaf, S.READ_FLAGS | os.O_DIRECTORY, dir_fd=parent)
            try:
                need(os.fstat(fd).st_uid == os.getuid(), 'part-fresh-directory-owner')
                S.no_xattrs(fd); os.fchmod(fd, mode); os.fsync(fd)
            finally: S.close_once(fd)
    write(work / 'part-dependencies.json', P.canonical([records[p] for p in P.ancestors(part)]), 0o444)
    # Only immutable bindings/data are exported; no origin process environment.
    values = {}
    for env, path in (('MRK_MACOS_ANDROID_HELPER_SHA256', 'mrk-android-register'),
                      ('MRK_MACOS_DESKTOP_FACADE_SHA256', 'mobile-release-kit-desktop'),
                      ('MRK_MACOS_ENTRY_SHA256', 'mrk-macos-entry'),
                      ('MRK_MACOS_RESIDENT_IMAGE_SHA256', 'libmrk_resident_image.dylib'),
                      ('MRK_MACOS_VAULT_HELPER_SHA256', 'vault-helper-target/' + P.TARGET + '/release/mrk-vault-keychain'),
                      ('MRK_MACOS_REMOVER_SHA256', 'remover-target/' + P.TARGET + '/release/mrk-macos-remove'),
                      ('MRK_MACOS_INSTALLED_CLI_SHA256', 'installed-cli-target/' + P.TARGET + '/release/mrk')):
        if os.path.lexists(work / path):
            with original(work / path, P.MEMBER_LIMIT) as (stream, info):
                values[env] = hashlib.file_digest(stream, 'sha256').hexdigest()
    if os.path.lexists(work / 'observer-build.jsonl'):
        name = observer_name(work); path = work / 'cargo-target' / P.TARGET / 'debug/deps' / name
        with original(path, P.MEMBER_LIMIT) as (stream, info): values['MRK_MACOS_OBSERVER_SHA256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
        values['MRK_MACOS_OBSERVER_BINARY'] = str(path)
    if os.path.lexists(work / 'input-result.json'):
        values['MRK_MACOS_INSTALL_INVENTORY_SHA256'] = json.loads(read(work / 'input-result.json', 2048))['inventorySha256']
        need(P.hex_data(values['MRK_MACOS_INSTALL_INVENTORY_SHA256']), 'part-inventory-data')
    values['MRK_IMAGE_RELEASE_ID'] = S.selected_build(S.source_build_selection(P.TARGET)).release
    with open(os.environ['GITHUB_ENV'], 'a', encoding='ascii') as out:
        for name, value in sorted(values.items()):
            need(type(value) is str and '\n' not in value and '\r' not in value, 'part-environment-data')
            out.write(name + '=' + value + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('freeze', 'restore'))
    parser.add_argument('--part', required=True, choices=tuple(ROSTER) + ('final-package',))
    args = parser.parse_args()
    work, workspace = host()
    (freeze if args.action == 'freeze' else restore)(args.part, work, workspace)
