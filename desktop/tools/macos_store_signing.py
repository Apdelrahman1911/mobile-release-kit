"""One fixed Store signing batch, using the existing Operation native owner.

TAR and Mach-O readers here inspect DATA only. No downloaded code is executed;
all codesign/keychain calls and their closure remain with Operation.
"""
from __future__ import annotations
import copy
import hashlib
import io
import json
import os
import re
from pathlib import Path
import stat
import struct
import tarfile
import time

PHASE = 'sign-store-runtime'
REF = 'refs/heads/verify/desktop-macos-store-signing'
ARCHIVE_LIMIT = 512 * 1024 * 1024
FILE_LIMIT = 64 * 1024 * 1024
ENTRY_LIMIT = 32768
NATIVE_COUNT = 133
INPUT_NATIVE_COUNT = 187
# The exact pinned gem compiler intermediates are not loadable Ruby extensions.
CRC_BUILD_MODULES = (
    "crc12_3gpp", "crc15", "crc16", "crc16_ccitt", "crc16_dnp", "crc16_genibus",
    "crc16_kermit", "crc16_modbus", "crc16_usb", "crc16_x_25", "crc16_xmodem", "crc16_zmodem",
    "crc24", "crc32", "crc32_bzip2", "crc32_jam", "crc32_mpeg", "crc32_posix", "crc32_xfer",
    "crc32c", "crc5", "crc64", "crc64_jones", "crc64_nvme", "crc64_xz", "crc8", "crc8_1wire")
BUILD_OBJECT_PATHS = frozenset(
    f"runtime/bundle/ruby/3.3.0/gems/digest-crc-0.7.0/ext/digest/{name}/{name}{suffix}.o"
    for name in CRC_BUILD_MODULES for suffix in ("", "_ext"))
# RubyGems' install cache contains another copy of the optional notifier app.
# It is not used by the frozen runtime. Keep all installed sources and notices;
# exclude only this lock-checksummed archive, not arbitrary cache contents.
NOTIFIER_CACHE_PATH = 'runtime/bundle/ruby/3.3.0/cache/terminal-notifier-2.0.0.gem'
NOTIFIER_CACHE_SHA256 = '7a0d2b2212ab9835c07f4b2e22a94cff64149dba1eed203c04835f7991078cea'
NOTIFIER_CACHE_BYTES = 1030656
OMISSION_PATHS = BUILD_OBJECT_PATHS | {NOTIFIER_CACHE_PATH}
WORK_SECONDS, HARD_SECONDS = 1500, 1620
ROLES = tuple(f'store-{index:03d}-{action}' for index in range(NATIVE_COUNT) for action in ('sign', 'verify'))
# 266*(3 capture + 1 native + 2*8 private census) + 40*8 auxiliary
# census + 128 source/acquisition originals = 5768, including consumed closes.
ORIGINAL_LIMIT = 8192
MAGICS = {b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xce',
          b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'}


class Refused(ValueError):
    pass


def need(value, reason):
    if not value:
        raise Refused('store-' + reason)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def archive_scan(body, native_check, *, native_count=NATIVE_COUNT):
    """Inspect every byte/name once before secrets; keep only bounded row DATA."""
    need(type(body) is bytes and 0 < len(body) <= ARCHIVE_LIMIT
         and native_count in (NATIVE_COUNT, INPUT_NATIVE_COUNT), 'archive-bound')
    rows, names, planned, total, natives = [], set(), {}, 0, []
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
        for entry in archive:
            name = entry.name[:-1] if entry.isdir() and entry.name.endswith('/') else entry.name
            parts = name.split('/')
            need(len(rows) < ENTRY_LIMIT and 0 < len(name) <= 507 and name.isascii()
                 and all(32 <= ord(c) < 127 and c != '\\' for c in name)
                 and parts[0] == 'runtime' and len(parts) <= 32
                 and all(p not in ('', '.', '..') for p in parts)
                 and name not in names and (entry.isdir() or entry.isfile())
                 and not entry.mode & ~0o777 and not entry.mode & 0o022
                 and 0 <= entry.size <= FILE_LIMIT, 'archive-entry')
            names.add(name)
            for end in range(1, len(parts) + 1):
                path = '/'.join(parts[:end])
                node = (path, end < len(parts) or entry.isdir())
                need(planned.setdefault(path.casefold(), node) == node and len(planned) <= ENTRY_LIMIT,
                     'archive-name-conflict')
            data = b''
            if entry.isfile():
                total += entry.size
                need(total <= ARCHIVE_LIMIT, 'archive-decoded-bound')
                with archive.extractfile(entry) as stream:
                    data = stream.read(FILE_LIMIT + 1)
                need(len(data) == entry.size, 'archive-truncated')
            else:
                need(entry.size == 0, 'archive-directory-data')
            native = data[:4] in MAGICS
            # A malformed native-named executable cannot silently become DATA.
            expected = entry.isfile() and (name == 'runtime/bin/ruby' or name.endswith(('.bundle', '.dylib')))
            # Bundler's ordinary .bundle configuration directory is not code.
            # Its child files remain fully inspected; native-named files still
            # fail closed unless they carry an admitted Mach-O header.
            need(not data.startswith((b'\x7fELF', b'MZ')) and (not expected or native), 'archive-native-header')
            if native:
                native_check(data, name)  # Every architecture/loader checked before any secret use.
                natives.append(name)
                need(len(natives) <= native_count, 'archive-native-count')
            rows.append({'path': name, 'directory': entry.isdir(), 'mode': entry.mode,
                         'bytes': len(data), 'sha256': sha(data), 'native': native})
    need('runtime/bin/ruby' in natives and len(natives) == native_count, 'archive-complete-native-roster')
    return rows


def identifier(name):
    need(type(name) is str and name.startswith('runtime/'), 'identifier-path')
    return 'dev.mobile-release-kit.desktop.store.' + sha(name.encode('ascii'))[:32]


def sign_arguments(path, entitlements, name, identity, requirement):
    need(isinstance(path, Path) and isinstance(entitlements, Path), 'native-path')
    selected = identifier(name)
    return ([ '/usr/bin/codesign', '--force', '--sign', identity[1], '--identifier', selected,
              '--options', 'runtime', '--entitlements', str(entitlements), '--timestamp', str(path)],
            ['/usr/bin/codesign', '--verify', '--strict', '--all-architectures', '--test-requirement',
             '=' + requirement(identity, selected), str(path)])


def native_policy(body, name, op, matcher):
    complete, minimum, _ = op.stager._macho_commands(body, target=op.target, system_only=True,
        allowed_kinds=(2,) if name == 'runtime/bin/ruby' else (2, 8))
    need(complete and minimum == [(1, 26 << 16)], 'native-loader-or-deployment')
    matcher.macho_records(body, op.arch)


def project_runtime_inventory(body, op, matcher):
    """Omit54 exact build objects and one authenticated optional-app cache.

    Ruby requires crc*_ext.bundle through its installed library/load path; these
    ext/digest/*.o are compiler intermediates, never signed runtime images.
    All other members, including installed sources/notices/extensions, stay.
    """
    objects = []
    def inspect(data, name):
        if name not in BUILD_OBJECT_PATHS:
            native_policy(data, name, op, matcher)
            return
        complete, minimum, records = op.stager._macho_commands(data, target=op.target,
            system_only=True, allowed_kinds=(1,))
        need(complete and minimum == [(1, 26 << 16)]
             and tuple(row[0] for row in records) == ((0x19, 0x32, 0x2e, 0x2, 0xb)
                 if op.target == op.stager.ARM_TARGET else (0x19, 0x32, 0x2, 0xb))
             and not any(row[2] for row in records), 'build-object-header')
        objects.append(name)
    original = archive_scan(body, inspect, native_count=INPUT_NATIVE_COUNT)
    need(len(objects) == 54 and set(objects) == BUILD_OBJECT_PATHS, 'build-object-exact-roster')
    cache = [row for row in original if row['path'] == NOTIFIER_CACHE_PATH]
    need(len(cache) == 1 and not cache[0]['directory'] and not cache[0]['native']
         and cache[0]['bytes'] == NOTIFIER_CACHE_BYTES and cache[0]['sha256'] == NOTIFIER_CACHE_SHA256,
         'notifier-cache-original')
    omitted = [{'path': row['path'], 'bytes': row['bytes'], 'sha256': row['sha256']}
               for row in original if row['path'] in OMISSION_PATHS]
    projected = [row for row in original if row['path'] not in OMISSION_PATHS]
    need(sum(row['native'] for row in projected) == NATIVE_COUNT, 'projected-native-roster')
    return original, projected, omitted


def validate_projection_receipt(receipt, rows):
    """Validate declared omissions; legacy readback is not notarization readiness."""
    caches = [row for row in rows if row['path'] == NOTIFIER_CACHE_PATH]
    expected_cache = {'path': NOTIFIER_CACHE_PATH, 'sha256': NOTIFIER_CACHE_SHA256, 'bytes': NOTIFIER_CACHE_BYTES}
    modern = 'omittedInstallCaches' in receipt
    if modern:
        declared = receipt['omittedInstallCaches']
        need(type(declared) is list and len(declared) == 1 and type(declared[0]) is dict
             and type(declared[0].get('bytes')) is int and declared[0] == expected_cache and not caches
             and receipt.get('nonNativeUnchangedScope') == 'retained-after-declared-projection',
             'notifier-cache-projection')
    else:
        need('nonNativeUnchangedScope' not in receipt and len(caches) == 1
             and not caches[0]['directory'] and not caches[0]['native']
             and {key: caches[0][key] for key in expected_cache} == expected_cache, 'legacy-notifier-cache')
    omitted = receipt.get('omittedBuildObjects')
    expected_counts = {'inputNativeCount': INPUT_NATIVE_COUNT, 'outputNativeCount': NATIVE_COUNT,
                       'outputMemberCount': len(rows), 'inputMemberCount': len(rows) + 54 + int(modern)}
    need(all(type(receipt.get(key)) is int and receipt[key] == number for key, number in expected_counts.items())
         and type(omitted) is list and len(omitted) == 54
         and all(type(row) is dict and set(row) == {'path', 'sha256', 'bytes'}
             and type(row['path']) is str and row['path'] in BUILD_OBJECT_PATHS
             and type(row['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', row['sha256'])
             and type(row['bytes']) is int and 0 < row['bytes'] <= FILE_LIMIT for row in omitted)
         and {row['path'] for row in omitted} == BUILD_OBJECT_PATHS
         and not any(row['path'] in BUILD_OBJECT_PATHS for row in rows), 'build-only-projection')


def clock(op, *, work=True):
    state, now = op.store_signing, time.monotonic_ns()
    need(type(now) is int and state['observed'] <= now < state['started'] +
         (WORK_SECONDS if work else HARD_SECONDS) * 10**9, 'aggregate-deadline')
    state['observed'] = now
    return now, state['started'] + (WORK_SECONDS if work else HARD_SECONDS) * 10**9


def credential_endpoint(op):
    clock(op)  # Acquisition is work, not an entry into the cleanup reserve.
    return op.store_signing['started'] + HARD_SECONDS * 10**9


def start(op, api, started):
    need(op.phase == PHASE and type(started) is int and started > 0, 'original-start')
    op.store_signing = {'api': api, 'started': started, 'observed': started, 'complete': False,
        'retiring': False, 'delivery': {}, 'inputs': [], 'rows': None, 'native': [], 'outputs': {}}
    clock(op)
    # Whole compressed PRE and POST, bounded TAR workspaces, one native pair,
    # source/row/call metadata: <3GiB owned DATA; not a process RSS guarantee.
    capacity = os.fstatvfs(op.work_entry['fd'])
    need(capacity.f_frsize > 0 and capacity.f_bavail * capacity.f_frsize >= 2 * 1024**3, 'disk-reserve')
    op.receipt.update(toolchain=None, helperIdentifier=None)


def io_call(op, label, action):
    clock(op, work=not op.store_signing['retiring'])
    need(op.stager_io_pending is None, 'io-overlap')
    op.stager_io_pending = label
    result = action()
    clock(op, work=not op.store_signing['retiring'])
    op.stager_io_pending = None
    return result


def write(op, parent, name, body, mode):
    need(type(body) is bytes and len(body) <= ARCHIVE_LIMIT, 'output-bound')
    api = op.store_signing['api']
    def create():
        op.recheck_directory(parent)
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent['fd'])
        entry = op.register(fd, 'store-' + name, 'file', parent['fd'], name)
        entry['parent_entry'] = parent
        position = 0
        while position < len(body):
            count = os.write(fd, body[position:position + 1024 * 1024])
            need(type(count) is int and count > 0, 'short-write')
            position += count
        os.fchmod(fd, mode)
        os.fsync(fd)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
             and info.st_gid == os.getgid() and stat.S_IMODE(info.st_mode) == mode, 'created-original')
        entry['identity'] = api.signature(info)
        need(op.read(entry) == body, 'output-readback')
        return entry
    return io_call(op, 'store-write', create)


def dispatch(op, role):
    state, context = op.store_signing, op.credential_active
    clock(op)
    need(state['rows'] is not None and not state['retiring'] and not op.errors
         and op.stager_io_pending is None and len(op.calls) < len(ROLES)
         and role == ROLES[len(op.calls)] and op.signing_mutation_pending == role.endswith('-sign')
         and context is not None and context.get('purpose') == PHASE and context.get('ready') is True
         and context.get('roles') == ROLES and not context.get('retiring')
         and all(c.get('returned') is True and c.get('capturesSettled') is True
                 and type(c.get('returncode')) is int and c['returncode'] == 0 for c in op.calls),
         'native-dispatch')


def native_call(op, role, argv):
    now, endpoint = clock(op)
    result = op.call(role, argv, op.native_environment(), cwd=op.work,
                    timeout=op.store_signing['api'].package_timeout_data(now, endpoint, 30), limit=65536)
    clock(op)
    need(result.returncode == 0 and not result.stdout, 'native-result')
    if role.endswith('-verify'):
        need(not result.stderr, 'verify-stderr')


def post(op):
    clock(op, work=not op.store_signing['retiring'])
    for entry, body in op.package_sources + op.store_signing['inputs']:
        need(op.read(entry) == body, 'source-input-post')


def prepare(op):
    state, api = op.store_signing, op.store_signing['api']
    need(op.signing is not None, 'configured-identity')
    empty = op.source_original('desktop/packaging/macos-empty-entitlements.plist', 'store-entitlements', 1024)
    entitlements = op.read(empty)
    need(sha(entitlements) == op.stager.SIGNED_ENTITLEMENTS_SHA256, 'empty-entitlements')
    op.package_sources.append((empty, entitlements))
    parent = op.directory(op.work_entry, 'store-original', 'store-original-directory')
    archive = op.original(parent, 'store-runtime.tar.gz', 'store-original-archive', ARCHIVE_LIMIT, (0o400,))
    original = op.read(archive)
    state['inputs'].append((archive, original))
    origin = op.original(parent, 'runtime-origin.json', 'store-service-origin', 16384, (0o400,))
    origin_body = op.read(origin)
    state['inputs'].append((origin, origin_body))
    upstream = api.tool_json(origin_body)
    need(type(upstream) is dict and upstream.get('signed') is False and upstream.get('arch') == op.arch
         and upstream.get('archiveSha256') == sha(original)
         and upstream.get('source') == '0039f79baa54318d58d87606335492f7ef2a90dd'
         and upstream.get('runId') == 38844616192 and upstream.get('runAttempt') == 1
         and upstream.get('artifactId') == (12022417782 if op.arch == 'arm64' else 12022823630), 'service-origin')
    matcher = op.signing_matcher()
    input_rows, before, omitted = io_call(op, 'store-preflight', lambda: project_runtime_inventory(original, op, matcher))
    state['rows'] = before
    post(op)
    destination, after, native_index = io.BytesIO(), [], 0
    with op.credential_scope(PHASE):
        with tarfile.open(fileobj=io.BytesIO(original), mode='r:gz') as source, \
                tarfile.open(fileobj=destination, mode='w:gz', format=tarfile.PAX_FORMAT) as target:
            for entry, row in zip(source, input_rows, strict=True):
                clock(op)
                data = b''
                if entry.isfile():
                    with source.extractfile(entry) as stream:
                        data = stream.read(FILE_LIMIT + 1)
                need(len(data) == row['bytes'] and sha(data) == row['sha256'], 'preimage-row')
                if row['path'] in OMISSION_PATHS:
                    continue  # Exact validated build-only leaf; original archive is unchanged.
                if row['native']:
                    index = native_index
                    native_index += 1
                    scratch = f'native-{index:03d}'
                    old = write(op, op.target_entry, scratch, data, 0o755)
                    path = op.work / op.target_name / scratch
                    arguments = sign_arguments(path, op.checkout / 'desktop/packaging/macos-empty-entitlements.plist',
                                               row['path'], op.signing, api.signing_requirement)
                    op.signing_mutation_pending = True
                    native_call(op, ROLES[2 * index], arguments[0])
                    current = op.original(op.target_entry, scratch, 'store-signed-original', FILE_LIMIT, (0o755,))
                    signed = op.read(current)
                    io_call(op, 'store-neutral-match', lambda: matcher.macho_content_valid(data, signed, op.arch, signing=True))
                    native_policy(signed, row['path'], op, matcher)
                    flags = api.python_code_flags(signed, op.arch, 'python-shipping', matcher)
                    op.close(old)
                    need(old['closed'] and not op.errors, 'preimage-close')
                    op.signing_mutation_pending = False
                    native_call(op, ROLES[2 * index + 1], arguments[1])
                    need(op.read(current) == signed, 'verified-original-post')
                    state['native'].append({'path': row['path'], 'identifier': identifier(row['path']),
                        'originalSha256': row['sha256'], 'signedSha256': sha(signed),
                        'signedBytes': len(signed), 'codeDirectoryFlags': flags})
                    op.close(current)
                    need(current['closed'] and not op.errors, 'signed-original-close')
                    # Only this exact consumed scratch file; never a caller input.
                    def retire_slot():
                        op.recheck_directory(op.target_entry)
                        need(api.signature(os.stat(scratch, dir_fd=op.target_entry['fd'], follow_symlinks=False)) == current['identity'],
                             'signed-slot-identity')
                        os.unlink(scratch, dir_fd=op.target_entry['fd'])
                    io_call(op, 'store-slot-retire', retire_slot)
                    data = signed
                changed = copy.copy(entry)
                changed.pax_headers = dict(entry.pax_headers)
                changed.size = len(data)
                # PAX size must follow the signed image, not its unsigned PRE.
                changed.pax_headers.pop('size', None)
                target.addfile(changed, io.BytesIO(data) if entry.isfile() else None)
                after.append(dict(row, bytes=len(data), sha256=sha(data)))
                need(destination.tell() <= ARCHIVE_LIMIT, 'derived-archive-bound')
        need(native_index == NATIVE_COUNT, 'signed-complete-native-roster')
        post(op)
    body = destination.getvalue()
    need(len(body) <= ARCHIVE_LIMIT, 'final-archive-bound')
    observed = io_call(op, 'store-final-preflight', lambda: archive_scan(body,
        lambda data, name: native_policy(data, name, op, matcher)))
    need(observed == after, 'derived-complete-readback')
    for left, right in zip(before, observed, strict=True):
        need(left == right if not left['native'] else all(left[k] == right[k]
             for k in ('path', 'directory', 'mode', 'native')), 'nonnative-or-roster-change')
    post(op)
    entry = write(op, op.work_entry, 'store-signed.tar.gz', body, 0o444)
    state['delivery']['store-signed.tar.gz'] = (entry, sha(body), len(body))
    op.close(entry)
    need(entry['closed'] and not op.errors, 'delivery-close')
    state['receipt'] = {'schemaVersion': 1, 'kind': 'macos-store-signed-v1', 'target': op.target,
        'source': op.environment['GITHUB_SHA'], 'runId': op.environment['GITHUB_RUN_ID'],
        'runAttempt': op.environment['GITHUB_RUN_ATTEMPT'], 'workflow': op.environment['GITHUB_WORKFLOW_REF'],
        'upstream': upstream, 'originalInventorySha256': sha(canonical(input_rows)),
        'inputMemberCount': len(input_rows), 'outputMemberCount': len(observed),
        'inputNativeCount': INPUT_NATIVE_COUNT, 'outputNativeCount': NATIVE_COUNT,
        'omittedBuildObjects': [row for row in omitted if row['path'] in BUILD_OBJECT_PATHS],
        'omittedInstallCaches': [row for row in omitted if row['path'] == NOTIFIER_CACHE_PATH],
        'nonNativeUnchangedScope': 'retained-after-declared-projection',
        'signedInventorySha256': sha(canonical(observed)), 'signedArchiveSha256': sha(body), 'signedArchiveBytes': len(body),
        'nativeMembers': state['native'], 'nonNativeUnchanged': True,
        'signer': {'teamIdentifier': op.signing[0], 'certificateSha1': op.signing[1],
                   'producerProfileSha256': sha(op.producer_profile), 'serviceProfileSha256': sha(op.service_profile)},
        'notarizationQualified': False, 'productReady': False, 'outerExitRequired': True}
    state['complete'] = True
    op.sha256 = sha(body)


def finish_ready(op):
    return (not op.errors and op.credential_known() and not op.credential_failed and op.credential_active is None
            and not op.signing_mutation_pending and op.stager_io_pending is None
            and all(c.get('returned') is True and c.get('capturesSettled') is True for c in op.calls))


def credential_cleanup_ready(op):
    """Artifact validity is not credential custody; unknown originals still are.

    A completed nonzero codesign can leave invalid scratch. Preserve that
    scratch/mutation latch, but retire the original private keychain if every
    actual consumer returned and every capture/FD operation is known.
    """
    context = op.credential_active
    return (op.phase == PHASE and context is not None and context.get('purpose') == PHASE
            and context.get('roles') == ROLES and op.credential_known() and not op.errors
            and op.stager_io_pending is None and not op.python_mutation_pending
            and 0 < len(op.calls) <= len(ROLES)
            and tuple(c.get('role') for c in op.calls) == ROLES[:len(op.calls)]
            and all(c.get('returned') is True and c.get('capturesSettled') is True
                    and type(c.get('returncode')) is int and 0 <= c['returncode'] <= 255 for c in op.calls))


def retire(op):
    if not finish_ready(op):
        return
    op.store_signing['retiring'] = True
    post(op)
    for name, (entry, identity) in op.store_signing['outputs'].items():
        def remove():
            op.recheck_directory(op.work_entry)
            need(entry['closed'] and op.store_signing['api'].signature(os.stat(
                name, dir_fd=op.work_entry['fd'], follow_symlinks=False)) == identity, 'capture-original')
            os.unlink(name, dir_fd=op.work_entry['fd'])
        io_call(op, 'store-capture-retire', remove)
    # Caller supplier and delivery remain intact. Operation retires only its
    # existing scratch target after every original descriptor is closed.


def output_record(op, name, entry):
    allowed = {'android-helper-' + role + suffix for role in ROLES
               for suffix in ('.stdout', '.stderr', '.status')}
    need(name in allowed and name not in op.store_signing['outputs'], 'capture-name')
    op.store_signing['outputs'][name] = (entry, op.store_signing['api'].signature(os.fstat(entry['fd'])))


def success(op):
    return (op.store_signing['complete'] and finish_ready(op)
            and tuple(c.get('role') for c in op.calls) == ROLES
            and tuple(c.get('role') for c in op.credential_calls) ==
                op.store_signing['api'].CREDENTIAL_ROLES[:17] + ('search-final', 'default-after')
            and len(op.credential_contexts) == 1 and op.credential_contexts[0]['purpose'] == PHASE)


def summary(op):
    result = dict(op.receipt)
    # Actual finite ledgers, not a made-up success receipt or truncated roster.
    for key in ('originalCalls', 'credentialOriginals'):
        records = result.pop(key)
        result[key + 'Count'] = len(records)
        result[key + 'Sha256'] = sha(canonical(records))
    return result


def publish_final(op):
    state, api = op.store_signing, op.store_signing['api']
    need(op.receipt['passed'] and success(op) and op.receipt['targetRetired']
         and op.receipt['originalClosesKnown'], 'publication-finality')
    clock(op, work=False)
    result = dict(state['receipt'], originalsClosed=True, sourcePost=True, inputPost=True,
                  nativeCallCount=len(op.calls), nativeCallsSha256=sha(canonical(op.calls)),
                  credentialCallCount=len(op.credential_calls), credentialContexts=op.credential_contexts)
    body = canonical(result) + b'\n'
    need(len(body) <= 256 * 1024, 'receipt-bound')
    fd = os.open(op.work, api.READ_FLAGS | os.O_DIRECTORY)
    try:
        need(api.directory_identity(os.fstat(fd)) == api.directory_identity(op.work.lstat()) == op.work_entry['identity'],
             'publication-directory')
        for name, (entry, _, _) in state['delivery'].items():
            need(api.signature(os.stat(name, dir_fd=fd, follow_symlinks=False)) == entry['identity'], 'delivery-original')
        target = os.open('store-signed-receipt.json', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o444, dir_fd=fd)
        try:
            position = 0
            while position < len(body):
                count = os.write(target, body[position:])
                need(count > 0, 'receipt-short-write')
                position += count
            os.fsync(target)
            need(os.pread(target, len(body) + 1, 0) == body, 'receipt-readback')
        finally:
            os.close(target)
    finally:
        os.close(fd)
    clock(op, work=False)
