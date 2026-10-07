#!/usr/bin/env python3
"""Fixed ARM engineering AGP locked replay B; never protected UI admission.

Fixed reviewed A DATA is pinned below; missing nomination still refuses before SDK/network.
The current-use cohort is derived from actual reviewed provisioned Mac evidence.
A receipt marker is not a licence or delegated agreement.
"""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import json
import os
import plistlib
from pathlib import Path
import re
import shlex
import shutil
import ssl
import stat
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

SOURCE = Path('/Users/runner/work/mobile-release-kit/mobile-release-kit')
REF = 'refs/heads/verify/desktop-macos-android-dependencies'
WORKFLOW = '.github/workflows/desktop-macos-android-dependencies.yml'
RUN_SCOPE = 'prepare-b'  # Fixed locked replay; reviewed A does not assert B success.
# Exact public A originals and distinct source-bound DATA review, not a B receipt.
B_DATA = {'schemaVersion': 1,
 'source': 'e4106b69437c55ffa16dada025f334f7fa47854b',
 'tree': 'c403360097467861208edfcf7b9f2e5ff751cf25',
 'run': 37672292531,
 'attempt': 1,
 'job': 112966835099,
 'artifactId': 11504893918,
 'artifactSha256': '2541d5407203df454070ae84a7ded0797eb523e2c682167881adadb341ca3f41',
 'reviewSha256': '25215bad11a28655c21ad86d4cc439ef3f589c6aca4ab54a6c99f6611d304fb7',
 'pythonExecutable': '/Library/Frameworks/Python.framework/Versions/3.14/bin/python',
 'resources': {'receipt.json': [5163,
                                '9d3a0ff5a5c3b6d7f5081275d1e7ccf820547c8a788ace47db003ee155c9d903'],
               'inventory.json': [70247,
                                  '8d1d81338e66793ab2dd6e466be89b4c6470e6a1f51475dc7e56d0e2e80bec38'],
               'buildscript-gradle.lockfile': [6566,
                                               'ff53ec4b7427f2da997ed040dd338b0086c856564fe7001a0d030583c778ac85'],
               'app-gradle.lockfile': [326,
                                       'b8ca8e27e9b203531b6bd0d08c8d9a906ba8fecf63a7797fbbb64cd34e316ec4']}}
B_DATA_ROSTER = {'receipt.json': 16384, 'inventory.json': 1 << 20,
                 'buildscript-gradle.lockfile': 32 << 10, 'app-gradle.lockfile': 32 << 10}
SDK_CURRENT_USE = {'existingSelectedReceiptId': '24333f8a63b6825ea9c5514f83c2829b004d1fee', 'files': {'build-tools/35.0.0/package.xml': {'bytes': 18408, 'mode': 420, 'ownerUid': 501, 'sha256': 'efe1bc3424e93863725a90df610fae21e29aca6634f99dd3510d5b42fa2ff049'}, 'build-tools/35.0.0/source.properties': {'bytes': 63, 'mode': 420, 'ownerUid': 501, 'sha256': '084847d70abc41284feee7ea717e7c92eab0d1be05f048c27445a359cfe109d8'}, 'licenses/android-sdk-license': {'bytes': 41, 'mode': 420, 'ownerUid': 501, 'sha256': 'c43fa37686457c3f18caa3607945f4ec52a9d1beaaad8117e50dc4e863270c85'}, 'platforms/android-35/package.xml': {'bytes': 18510, 'mode': 420, 'ownerUid': 501, 'sha256': '7bca67e2f0f7258856d6f7ff0aa1a883e67ec8cce2553dbaf56baa79876e657f'}, 'platforms/android-35/source.properties': {'bytes': 257, 'mode': 420, 'ownerUid': 501, 'sha256': '2c3764446f335ad2cc44383a0360fe247620b7c774ec100d5087771ac8ed3b28'}}, 'image': {'ImageOS': 'macos26', 'ImageVersion': '20260907.0351.1'}, 'licenseDefinitionSha256': 'aaf80cd0aee7e569ffa8a4be1b61189c0fefccf23068e38dfafe336289b8c723', 'productVersion': '26.6.2', 'root': '/Users/runner/Library/Android/sdk'}  # Reviewed observation3f082944, never legal authority.
CHUNK = 65536
TOOL_BYTES = 1 << 30
READ_BYTES = 8 << 30
FILES = 16384
ENTRIES = 32768
MAVEN_BYTES = 256 << 20
PHASE_SECONDS = 1200
ACQUISITION_SECONDS = 900
# Filled below from immutable current SOURCE, not an historical body store.
PINS = {'desktop/tools/macos_android_supplier_preparation.py': [64306, '1d16d1e6af1d6d7795f36bef1bef89efbc7f05f80ac5e869216ad5225e536808'], 'desktop/tools/macos_android_supplier_correspondence.py': [53703, 'f0234fa1f56f9e5ba81a5619b6a8ae4605eefbd13e5157dd991657f7703faf29'], 'desktop/tools/macos_normal_ui_runner.py': [108597, '20b96a54f6b44e8098be9dd16baef9dcd33563858ff98dae069521dd697cd9b2']}
ARCHIVES = [{'role': 'jdk', 'bytes': 185851019, 'sha256': '196d13ba5f10414bef7f6a05a9b3f00edacb18ebacef2b99485db9e2ee18f0e8', 'url': 'https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20.1%2B1/OpenJDK17U-jdk_aarch64_mac_hotspot_17.0.20.1_1.tar.gz', 'archivePrefix': 'jdk-17.0.20.1+1'}, {'role': 'sdk-platform', 'bytes': 64273788, 'sha256': '0988cacad01b38a18a47bac14a0695f246bc76c1b06c0eeb8eb0dc825ab0c8e0', 'url': 'https://dl.google.com/android/repository/platform-35_r02.zip', 'archivePrefix': 'android-35'}, {'role': 'sdk-build-tools', 'bytes': 76857898, 'sha256': '530cdbd1ec315e1477624d7ed2f0f2962108d69f36eddba5894cef9ea2cedb48', 'url': 'https://dl.google.com/android/repository/build-tools_r35_macosx.zip', 'archivePrefix': 'android-15'}, {'role': 'gradle', 'bytes': 138068841, 'sha256': '6f74b601422d6d6fc4e1f9a1ab6522f642c2fdcbc15ae33ebd30ba3d7198e854', 'url': 'https://github.com/gradle/gradle-distributions/releases/download/v8.14.5/gradle-8.14.5-bin.zip', 'archivePrefix': 'gradle-8.14.5'}, {'role': 'aapt2', 'bytes': 4339472, 'sha256': '5d0aec6851fffbc9f6c8a8b50390c0bc976aa0ddf57a8a3a39061ed54b609ad1', 'url': 'https://dl.google.com/dl/android/maven2/com/android/tools/build/aapt2/8.9.2-12782657/aapt2-8.9.2-12782657-osx.jar', 'archivePrefix': '8.9.2-12782657-osx'}]
RESOURCES = {'desktop/tools/android_dependency_preparation_data/project-v1.json': [5761, '17aaefbea83fb4b389e10d1ac01f9926562712b95253f7af5f2c6fab546b1dd4'], 'desktop/tools/android_dependency_preparation_data/verification-v1.xml': [90045, '5d00856c785363da964e00da72ad38571cfd088da915ebe86cf20640bb1c7545']}
SDK_METADATA = [{'bytes': 17832, 'origin': 'committed-generated-sdk-package-metadata-not-vendor-archive-member-not-acceptance', 'path': 'desktop/macos-installed-inputs/android-sdk/platform-35-package.xml', 'sha256': '385364dad6ba50838ec90abc8e4593976e0e0c54c87cf703857ba0a1aad63fe2', 'target': 'sdk/platforms/android-35/package.xml'}, {'bytes': 17719, 'origin': 'committed-generated-sdk-package-metadata-not-vendor-archive-member-not-acceptance', 'path': 'desktop/macos-installed-inputs/android-sdk/build-tools-35-package.xml', 'sha256': '6f7a9969f1bb25e39ae22fa5690b878e6806217453acf3b534712fb3a76ad1d4', 'target': 'sdk/build-tools/35.0.0/package.xml'}]
N = P = C = None

class Refused(Exception):
    pass

def need(condition, code):
    if not condition:
        raise Refused(code)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()

def nine(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def chain(path, *, retained=False):
    """Bounded no-follow originals; selected observation retains named bindings."""
    need(path.is_absolute() and '..' not in path.parts and len(path.parts) <= 32, 'path-shape')
    fds, originals = [], []
    try:
        for name in path.parts:
            parent = fds[-1] if fds else None
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            fds.append(fd)
            state = nine(os.fstat(fd))
            originals.append((name, state[:5]))
            need(stat.S_ISDIR(state[2]) and state[3] in (0, os.getuid())
                 and not state[2] & 0o022
                 and nine(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5] == state[:5], 'parent-authority')
        return (fds, originals) if retained else fds
    except BaseException:
        # Include an adopted FD even if its first fstat did not return.
        failed = False
        for fd in reversed(fds):
            try: os.close(fd)
            except BaseException: failed = True
        fds.clear()
        # The original adoption/authority failure remains primary.
        raise


def recheck_chain(fds, originals):
    need(len(fds) == len(originals) and bool(fds), 'ancestor-original-shape')
    for index, (fd, (name, before)) in enumerate(zip(fds, originals)):
        parent = fds[index - 1] if index else None
        need(nine(os.fstat(fd))[:5] == before
             == nine(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5], 'ancestor-original-post')


def close_chain(fds, originals, *, file_fd=None):
    """Consume all originals once and preserve this call's first own failure."""
    failure = None
    try: recheck_chain(fds, originals)
    except BaseException as error: failure = error
    closing = fds[:] + ([] if file_fd is None else [file_fd])
    fds.clear()  # Retirement precedes consuming closes; no numeric retry.
    for fd in reversed(closing):
        try: os.close(fd)
        except BaseException:
            if failure is None: failure = Refused('original-close-unknown')
    if failure is not None: raise failure


def read(path, limit, *, clock=None):
    fds, originals = chain(path.parent, retained=True)
    fd = None
    primary = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fds[-1])
        before = nine(os.fstat(fd))
        need(stat.S_ISREG(before[2]) and before[3] in (0, os.getuid()) and before[5] == 1
             and not before[2] & 0o022 and 0 <= before[6] <= limit, 'original-file')
        chunks = []
        for at in range(0, before[6], CHUNK):
            if clock: clock.check()
            part = os.pread(fd, min(CHUNK, before[6] - at), at)
            need(len(part) == min(CHUNK, before[6] - at), 'original-short')
            chunks.append(part)
        need(not os.pread(fd, 1, before[6]) and nine(os.fstat(fd)) == before
             and nine(os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)) == before, 'original-post')
        recheck_chain(fds, originals)
        return b''.join(chunks), before
    except BaseException as error:
        primary = error
        raise
    finally:
        failure = None
        if fd is not None:
            closing, fd = fd, None
            try: os.close(closing)
            except BaseException: failure = Refused('original-close-unknown')
        try: close_chain(fds, originals)
        except BaseException as error:
            if failure is None: failure = error
        if failure is not None and primary is None: raise failure


def admit_work(path):
    fds, originals = chain(path, retained=True)
    try:
        state = nine(os.fstat(fds[-1]))
        need(state[3] == os.getuid() and stat.S_IMODE(state[2]) == 0o700, 'private-work-original')
        return {'path': path, 'fds': fds, 'originals': originals}
    except BaseException:
        try: close_chain(fds, originals)
        except BaseException: pass
        raise


def publish_json(private, name, value):
    """Only two closed diagnostic leaves, through the retained private original."""
    limits = {'sdk-observation.json': 16384, 'observe-sdk-failure.json': 4096,
              'prepare-b-failure.json': 4096, 'acquire-failure.json': 4096, 'cleanup-failure.json': 4096}
    need(name in limits, 'diagnostic-leaf')
    raw = encoded(value)
    need(0 < len(raw) <= limits[name], 'diagnostic-bound')
    fds, originals = private['fds'], private['originals']
    recheck_chain(fds, originals)
    parent = fds[-1]; fd = None
    primary = None
    try:
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        state = nine(os.fstat(fd))
        need(stat.S_ISREG(state[2]) and stat.S_IMODE(state[2]) == 0o600
             and state[3] == os.getuid() and state[5] == 1 and state[6] == 0, 'diagnostic-original')
        view = memoryview(raw)
        while view:
            count = os.write(fd, view); need(count > 0, 'diagnostic-write-short'); view = view[count:]
        os.fsync(fd)
        before = nine(os.fstat(fd))
        need(before[:6] == state[:6] and before[6] == len(raw)
             and os.pread(fd, len(raw), 0) == raw and not os.pread(fd, 1, len(raw))
             and nine(os.fstat(fd)) == before
             == nine(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'diagnostic-post')
        recheck_chain(fds, originals)
        os.fsync(parent)
    except BaseException as error:
        primary = error
        raise
    finally:
        if fd is not None:
            closing, fd = fd, None
            try: os.close(closing)
            except BaseException:
                if primary is None: raise Refused('diagnostic-close-unknown') from None
    recheck_chain(fds, originals)


def publish_preparation(work, relative, raw, *, clock=None):
    """Only fixed B leaves; same retained-parent/original readback as diagnostics."""
    limits = {'tool-roster.json': 4 << 20, 'directory-roster.json': 4 << 20,
        'acquisition.json': 16384, 'evidence/acquisition-commands.json': 16384,
        'evidence/failed-commands.json': 16384, 'evidence/gradle-failure.json': 12 << 10,
        'evidence/inventory.json': 1 << 20, 'evidence/inventory-drift.json': 1 << 20,
        'evidence/buildscript-gradle.lockfile': 32 << 10, 'evidence/app-gradle.lockfile': 32 << 10,
        'evidence/receipt.json': 16384, 'run/project/gradle/verification-metadata.xml': 128 << 10,
        'run/project/buildscript-gradle.lockfile': 32 << 10, 'run/project/app/gradle.lockfile': 32 << 10}
    for name in ('settings.gradle', 'build.gradle', 'app/build.gradle', 'app/src/main/AndroidManifest.xml',
                 'app/src/main/java/org/example/saved/MainActivity.java',
                 'gradle/wrapper/gradle-wrapper.properties', 'release/version.properties',
                 'release/mobile-release.json', '.gitignore'):
        limits['run/project/' + name] = 16384
    need(relative in limits and type(raw) is bytes and 0 < len(raw) <= limits[relative], 'preparation-output-bound')
    path = work / relative; held = chain(path.parent, retained=True); fd = None; primary = None
    try:
        if clock: clock.check()
        fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=held[0][-1])
        before = nine(os.fstat(fd))
        need(stat.S_ISREG(before[2]) and stat.S_IMODE(before[2]) == 0o600
             and before[3] == os.getuid() and before[5:7] == (1, 0), 'preparation-output-original')
        for at in range(0, len(raw), CHUNK):
            view = memoryview(raw)[at:at + CHUNK]
            while view:
                if clock: clock.check()
                count = os.write(fd, view); need(count > 0, 'preparation-output-short'); view = view[count:]
        os.fsync(fd); after = nine(os.fstat(fd))
        need(after[:6] == before[:6] and after[6] == len(raw), 'preparation-output-size')
        for at in range(0, len(raw), CHUNK):
            if clock: clock.check()
            need(os.pread(fd, min(CHUNK, len(raw) - at), at) == raw[at:at + CHUNK], 'preparation-output-readback')
        need(not os.pread(fd, 1, len(raw)) and nine(os.fstat(fd)) == after
             == nine(os.stat(path.name, dir_fd=held[0][-1], follow_symlinks=False)), 'preparation-output-post')
        recheck_chain(*held); os.fsync(held[0][-1])
    except BaseException as error:
        primary = error; raise
    finally:
        try: close_chain(*held, file_fd=fd)
        except BaseException:
            if primary is None: raise
    if clock: clock.check()


def clock_record(value, seconds):
    need(type(value) is dict and set(value) == {'startNs', 'deadlineNs', 'beforePublicationNs',
         'postCloseDeadlineRequired'} and value['postCloseDeadlineRequired'] is True, 'receipt-clock')
    need(all(type(value[k]) is str and re.fullmatch('[0-9]{1,20}', value[k])
         for k in ('startNs', 'deadlineNs', 'beforePublicationNs')), 'receipt-clock-number')
    start, deadline, before = (int(value[k]) for k in ('startNs', 'deadlineNs', 'beforePublicationNs'))
    need(start <= before < deadline and deadline - start == seconds * 1_000_000_000, 'receipt-clock-endpoint')


def current_observation(work, clock):
    raw, identity = read(work / 'sdk-observation.json', 16384, clock=clock)
    value = N.document(raw)
    need(identity[3] == os.getuid() and stat.S_IMODE(identity[2]) == 0o600
         and value.get('source') == os.environ['GITHUB_SHA']
         and value.get('classification') == 'current-run-provisioned-sdk-observation-not-license-entitlement'
         and value.get('acceptancePerformed') is False and 'reason' not in value, 'current-observation-original')
    admit_sdk_current_use(value)
    return digest(raw)


def observed_python_executable():
    # Public API metadata from the admitted hosted Python, never a path selector.
    value = sys.executable
    need(type(value) is str and 1 < len(value) <= 1024 and value.startswith('/')
         and all('!' <= c <= '~' for c in value)
         and all(part not in ('', '.', '..') for part in value.split('/')[1:]), 'python-executable-path')
    return value


def acquisition_receipt(work, clock):
    raw, _ = read(work / 'acquisition.json', 16384, clock=clock); value = N.document(raw)
    need(set(value) == {'status', 'source', 'workflow', 'ref', 'phase', 'archives', 'archiveBytes',
         'toolBytes', 'readBytes', 'files', 'entries', 'stockCaSha256', 'nativeExecuted',
         'protectedRegistration', 'sdkObservationSha256', 'sdkMetadata', 'toolRosterSha256', 'pythonExecutable', 'phaseClock'}, 'acquisition-fields')
    need(value['status'] == 'closed' and value['source'] == os.environ['GITHUB_SHA']
         and value['workflow'] == WORKFLOW and value['ref'] == REF and value['phase'] == 'acquisition'
         and value['archives'] == ARCHIVES and value['archiveBytes'] == 469391018
         and value['nativeExecuted'] is False and value['protectedRegistration'] is False
         and value['sdkMetadata'] == SDK_METADATA
         and value['sdkObservationSha256'] == current_observation(work, clock), 'acquisition-bindings')
    need(value['pythonExecutable'] == observed_python_executable(), 'acquisition-python-binding')
    for key, maximum in (('toolBytes', TOOL_BYTES), ('readBytes', READ_BYTES), ('files', FILES), ('entries', ENTRIES)):
        need(type(value[key]) is int and 0 < value[key] <= maximum, 'acquisition-resource')
    need(type(value['stockCaSha256']) is str and re.fullmatch('[0-9a-f]{64}', value['stockCaSha256']), 'acquisition-ca-digest')
    clock_record(value['phaseClock'], 810)
    rows, _ = read(work / 'tool-roster.json', 4 << 20, clock=clock)
    dirs, _ = read(work / 'directory-roster.json', 4 << 20, clock=clock)
    need(value['toolRosterSha256'] == digest(rows + dirs), 'acquisition-tool-roster')
    return value, digest(raw)


def file_digest(path, limit, clock):
    held = chain(path.parent, retained=True); fd = None; primary = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=held[0][-1])
        before = nine(os.fstat(fd))
        need(stat.S_ISREG(before[2]) and before[3] == os.getuid() and before[5] == 1
             and not before[2] & 0o022 and 0 <= before[6] <= limit, 'artifact-original')
        sha = hashlib.sha256(); prefix = b''
        for at in range(0, before[6], CHUNK):
            clock.check(); amount = min(CHUNK, before[6] - at); part = os.pread(fd, amount, at)
            need(len(part) == amount, 'artifact-short'); sha.update(part)
            if at == 0: prefix = part[:4]
        clock.check()
        need(not os.pread(fd, 1, before[6]) and nine(os.fstat(fd)) == before
             == nine(os.stat(path.name, dir_fd=held[0][-1], follow_symlinks=False)), 'artifact-post')
        recheck_chain(*held)
        return before[6], sha.hexdigest(), prefix
    except BaseException as error:
        primary = error; raise
    finally:
        try: close_chain(*held, file_fd=fd)
        except BaseException:
            if primary is None: raise


def load(name, relative):
    path = SOURCE / relative
    raw, before = read(path, 1 << 20)
    need((len(raw), digest(raw)) == tuple(PINS[relative]), 'source-module-pin')
    need(name not in sys.modules, 'module-collision')
    spec = importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None, 'module-spec')
    module = importlib.util.module_from_spec(spec)
    registered = False
    try:
        sys.modules[name] = module; registered = True
        # Execute THIS authenticated byte string. No loader path reread or pycache.
        exec(compile(raw, str(path), 'exec', dont_inherit=True), module.__dict__)
        need(sys.modules.get(name) is module, 'source-module-registry')
        need(read(path, 1 << 20) == (raw, before), 'source-module-post')
        return module
    except BaseException:
        if registered and sys.modules.get(name) is module:
            del sys.modules[name]
        raise


def context():
    need(sys.platform == 'darwin' and os.uname().machine == 'arm64'
         and os.getuid() != 0 and os.geteuid() == os.getuid()
         and sys.version_info[:3] == (3, 14, 7)
         and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode, 'fixed-native-python-host')
    env = os.environ
    need(env.get('GITHUB_REPOSITORY') == 'Apdelrahman1911/mobile-release-kit'
         and env.get('GITHUB_EVENT_NAME') == 'push' and env.get('GITHUB_REF') == REF
         and env.get('GITHUB_WORKFLOW_SHA') == env.get('GITHUB_SHA')
         and re.fullmatch('[0-9a-f]{40}', env.get('GITHUB_SHA', ''))
         and env.get('GITHUB_WORKFLOW_REF') == env['GITHUB_REPOSITORY'] + '/' + WORKFLOW + '@' + REF
         and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
         and env.get('RUNNER_OS') == 'macOS' and env.get('RUNNER_ARCH') == 'ARM64'
         and env.get('GITHUB_WORKSPACE') == str(SOURCE), 'fixed-event-source-host')
    value = env.get('MRK_ANDROID_PREPARATION_WORK', '')
    need(re.fullmatch('/Users/runner/work/_temp/mrk-android-dependencies[.][A-Za-z0-9]{8}', value), 'private-work-name')
    work = Path(value)
    fds, originals = chain(work, retained=True)
    primary = None
    try:
        s = os.fstat(fds[-1])
        need(s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o700, 'private-work-original')
    except BaseException as error:
        primary = error
        raise
    finally:
        try: close_chain(fds, originals)
        except BaseException:
            if primary is None: raise
    return work

def clean_environment(work):
    return {'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'PATH': '/usr/bin:/bin',
            'HOME': str(work), 'TMPDIR': str(work)}

def observe_sdk_current_use(work, *, private=None, clock=None):
    """Five fixed readonly SDK originals; absence is DATA, never legal acceptance."""
    owned_private = private is None
    if owned_private: private = admit_work(work)
    primary = None
    try:
        if clock is None: clock = N.PhaseClock(30)
        report = {'classification': 'current-run-provisioned-sdk-observation-not-license-entitlement',
                  'source': os.environ['GITHUB_SHA'], 'status': 'refused', 'files': {}}
        try:
            root = os.environ.get('MRK_PROVISIONED_SDK_ROOT', '')
            need(root == '/Users/runner/Library/Android/sdk', 'fixed-provisioned-sdk-root-unavailable')
            image = {k: os.environ.get(k, '') for k in ('ImageOS', 'ImageVersion')}
            need(all(re.fullmatch('[A-Za-z0-9._-]{1,80}', v) for v in image.values()), 'hosted-image-metadata-unavailable')
            raw, identity = read(Path('/System/Library/CoreServices/SystemVersion.plist'), 65536, clock=clock)
            system = plistlib.loads(raw)
            need(identity[3] == 0 and re.fullmatch(r'26(?:\.[0-9]{1,3}){0,2}', system.get('ProductVersion', '')), 'actual-macos26')
            report.update(root=root, image=image, productVersion=system['ProductVersion'])
            names = ('licenses/android-sdk-license', 'platforms/android-35/source.properties',
                     'platforms/android-35/package.xml', 'build-tools/35.0.0/source.properties',
                     'build-tools/35.0.0/package.xml')
            bodies = {}
            for name in names:
                raw, identity = read(Path(root) / name, 4096 if name.startswith('licenses/') else 65536, clock=clock)
                bodies[name] = raw
                report['files'][name] = {'bytes': len(raw), 'sha256': digest(raw),
                                         'ownerUid': identity[3], 'mode': stat.S_IMODE(identity[2])}
            marker = bodies[names[0]]
            need(re.fullmatch(rb'\n?(?:[0-9a-f]{40}\n)*[0-9a-f]{40}\n?', marker), 'existing-sdk-receipt-shape')
            ids = marker.decode('ascii').strip().splitlines()
            need(len(ids) == len(set(ids)) and len(ids) <= 64, 'existing-sdk-receipt-bound')
            definition = 'aaf80cd0aee7e569ffa8a4be1b61189c0fefccf23068e38dfafe336289b8c723'
            selected = '24333f8a63b6825ea9c5514f83c2829b004d1fee'
            need(selected in ids, 'selected-sdk-receipt-absent')
            packages = []
            for scope, package, revision in [('platforms/android-35', 'platforms;android-35', '2'),
                                             ('build-tools/35.0.0', 'build-tools;35.0.0', '35.0.0')]:
                props = P.properties(bodies[scope + '/source.properties'], {'Pkg.Revision', 'AndroidVersion.ApiLevel'})
                need(props.get('Pkg.Revision') == revision and (scope.startswith('build-tools/')
                     or props.get('AndroidVersion.ApiLevel') == '35'), 'provisioned-sdk-version')
                raw = bodies[scope + '/package.xml']
                need(b'<!DOCTYPE' not in raw and b'<!ENTITY' not in raw, 'sdk-xml-declarations')
                xml = ET.fromstring(raw)
                licenses = [node for node in xml if node.tag.rsplit('}', 1)[-1] == 'license']
                locals_ = [node for node in xml if node.tag.rsplit('}', 1)[-1] == 'localPackage']
                need(len(licenses) == len(locals_) == 1 and licenses[0].get('id') == 'android-sdk-license'
                     and locals_[0].get('path') == package, 'sdk-package-identity')
                text = licenses[0].text
                need(type(text) is str and len(text.encode()) <= 32768, 'sdk-license-definition-bound')
                # Existing repository31.9.2 TrimStringAdapter correspondence rule.
                text = re.sub(r'(?<=\s)[ \t]*', '', text, flags=re.ASCII)
                text = re.sub(r'(?<!\n)\n(?!\n)', ' ', text)
                text = re.sub(r' +', ' ', text).strip(''.join(chr(n) for n in range(33)))
                normalized = text.encode('utf-8')
                need(len(normalized) == 16960 and digest(normalized) == definition
                     and hashlib.sha1(normalized).hexdigest() == selected, 'sdk-license-definition-mismatch')
                uses = [node for node in locals_[0] if node.tag.rsplit('}', 1)[-1] == 'uses-license']
                need(len(uses) == 1 and uses[0].attrib == {'ref': 'android-sdk-license'}, 'sdk-package-license-reference')
                packages.append({'package': package, 'properties': props})
            report.update(status='observed-not-admitted', packages=packages,
                          licenseDefinitionSha256=definition, existingSelectedReceiptId=selected,
                          receiptIdCount=len(ids), originalsClosed=True, acceptancePerformed=False)
            clock.check()
        except BaseException as error:
            # A caught interruption after positive staging must not preserve success.
            report['status'] = 'refused'
            for key in ('originalsClosed', 'packages', 'licenseDefinitionSha256',
                        'existingSelectedReceiptId', 'receiptIdCount', 'acceptancePerformed'):
                report.pop(key, None)
            clock.failed = True
            code = str(error) if isinstance(error, Refused) else 'sdk-observation-original-failure'
            report['reason'] = code if re.fullmatch('[a-z0-9-]{1,96}', code) else 'sdk-observation-original-failure'
        publish_json(private, 'sdk-observation.json', report)
        need(report['status'] == 'observed-not-admitted' and 'reason' not in report, 'sdk-observation-refused')
        clock.finish()
        return report
    except BaseException as error:
        primary = error; raise
    finally:
        if owned_private:
            try: close_chain(private['fds'], private['originals'])
            except BaseException:
                if primary is None: raise


def admit_sdk_current_use(observed):
    # No environment, old inode receipt, or licence marker can supply this SOURCE policy.
    need(SDK_CURRENT_USE is not None, 'provisioned-sdk-current-use-not-admitted')
    need(observed['status'] == 'observed-not-admitted' and observed['originalsClosed'] is True,
         'provisioned-sdk-originals-unavailable')
    nomination = {key: observed[key] for key in ('root', 'image', 'productVersion',
                  'files', 'licenseDefinitionSha256', 'existingSelectedReceiptId')}
    need(nomination == SDK_CURRENT_USE, 'provisioned-sdk-source-nomination-mismatch')
    # This only recognizes the reviewed provisioned cohort; it grants no licence.


class Acquisition:
    """One fixed acquisition role budget; not a reusable resolver/owner."""
    def __init__(self, work):
        self.work = work
        self.clock = N.PhaseClock(810)
        self.reads = 0
        self.writes = 0
        self.downloads = 0
        self.entries = 0
        self.files = 0
        self.roster = []
        self.roster_bytes = 3
        self.directory_bytes = 3
        self.active = None
        self.archive_fd = None
        self.archive_before = None
        self.archive_path = None
        self.role = None
        self.directories = {}

    def point(self): self.clock.check()

    def charge_read(self, amount):
        self.point()
        need(0 <= amount <= CHUNK and self.reads + amount <= READ_BYTES, 'acquisition-read-bound')
        self.reads += amount

    def read_at(self, at, count):
        self.charge_read(count)
        return os.pread(self.archive_fd, count, at)

    def checkpoint(self): self.point()

    def verify_binding(self):
        self.point()
        need(nine(os.fstat(self.archive_fd)) == self.archive_before
             == nine(os.stat(self.archive_path, follow_symlinks=False)), 'archive-original-post')

    def parent(self, relative):
        parts = P.relative(relative)
        fds, originals = chain(self.work / 'tools', retained=True)
        prefix = []
        try:
            for part in parts[:-1]:
                self.point(); prefix.append(part)
                try:
                    need(self.entries < ENTRIES, 'directory-entry-bound')
                    os.mkdir(part, 0o700, dir_fd=fds[-1]); self.entries += 1
                except FileExistsError: pass
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fds[-1])
                fds.append(fd); state = nine(os.fstat(fd)); originals.append((part, state[:5]))
                need(state[3] == os.getuid() and stat.S_IMODE(state[2]) == 0o700, 'private-tool-directory')
                relative_dir = '/'.join(prefix)
                if relative_dir not in self.directories:
                    self.directory_bytes += len(encoded({relative_dir: list(state[:5])}))
                    need(self.directory_bytes <= 4 << 20, 'directory-roster-bound')
                    self.directories[relative_dir] = list(state[:5])
                need(self.directories[relative_dir] == list(state[:5]), 'tool-directory-changed')
            recheck_chain(fds, originals)
            return (fds, originals), parts[-1]
        except BaseException:
            try: close_chain(fds, originals)
            except BaseException: pass
            raise

    def append_row(self, row):
        # Incremental conservative charge; avoid an unbounded intermediate roster.
        self.roster_bytes += len(encoded(row)) + 1
        need(self.roster_bytes <= 4 << 20 and self.files < FILES, 'tool-roster-bound')
        self.roster.append(row); self.files += 1


    def target(self, name):
        prefix = self.role['archivePrefix']
        if self.role['role'] == 'aapt2':
            return 'gradle/native/aapt2/' + name if name in ('aapt2', 'NOTICE') else None
        need(name == prefix or name.startswith(prefix + '/'), 'fixed-archive-prefix')
        suffix = name[len(prefix):].lstrip('/')
        roots = {'jdk': 'jdk/temurin-17.jdk', 'sdk-platform': 'sdk/platforms/android-35',
                 'sdk-build-tools': 'sdk/build-tools/35.0.0', 'gradle': 'gradle'}
        return roots[self.role['role']] + ('/' + suffix if suffix else '')

    def begin(self, row):
        self.point()
        need(self.active is None and row[1] == 'file', 'archive-writer-order')
        target = self.target(row[0])
        if target is None: return
        need(row[3] <= 512 << 20 and self.writes + row[3] <= TOOL_BYTES
             and self.files < FILES, 'tool-write-bound')
        mode = row[2] & 0o7777
        need(mode in (0o444, 0o555, 0o644, 0o755), 'unsupported-vendor-file-mode')
        held, leaf = self.parent(target)
        fd = None; primary = None; transferred = False
        try:
            fd = os.open(leaf, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=held[0][-1])
            state = nine(os.fstat(fd))
            need(state[3] == os.getuid() and state[5] == 1 and state[6] == 0
                 and stat.S_IMODE(state[2]) == 0o600, 'new-tool-original')
            recheck_chain(*held)
            self.active = (fd, held, leaf, target, row[3], 0, hashlib.sha256(), mode)
            transferred = True
        except BaseException as error:
            primary = error; raise
        finally:
            if not transferred:
                try: close_chain(*held, file_fd=fd)
                except BaseException:
                    if primary is None: raise


    def block(self, name, offset, raw):
        if self.target(name) is None: return
        self.point()
        fd, parents, leaf, target, size, at, sha, mode = self.active
        need(offset == at and len(raw) <= CHUNK and at + len(raw) <= size, 'tool-block-order')
        view = memoryview(raw)
        while view:
            self.point()
            n = os.write(fd, view)
            need(n > 0, 'tool-write-short')
            view = view[n:]
        sha.update(raw)
        self.writes += len(raw)
        self.active = fd, parents, leaf, target, size, at + len(raw), sha, mode

    def end(self, row):
        if self.target(row[0]) is None: return
        fd, held, leaf, target, size, at, sha, mode = self.active
        self.active = None; primary = None
        try:
            need(at == size and sha.hexdigest() == row[4], 'tool-payload-digest')
            os.fsync(fd)
            before = nine(os.fstat(fd)); observed = hashlib.sha256()
            for pos in range(0, size, CHUNK):
                amount = min(CHUNK, size - pos); self.charge_read(amount)
                data = os.pread(fd, amount, pos)
                need(len(data) == amount, 'tool-readback-short'); observed.update(data)
            self.charge_read(1)
            need(not os.pread(fd, 1, size) and observed.hexdigest() == row[4]
                 and nine(os.fstat(fd)) == before
                 == nine(os.stat(leaf, dir_fd=held[0][-1], follow_symlinks=False)), 'tool-readback-post')
            recheck_chain(*held)
            self.append_row({'path': target, 'bytes': size, 'sha256': row[4],
                             'vendorMode': row[2], 'mode': mode & ~0o222, 'identity': list(before)})
        except BaseException as error:
            primary = error; raise
        finally:
            try: close_chain(*held, file_fd=fd)
            except BaseException:
                if primary is None: raise


    def terminal_row(self, row):
        self.point(); self.entries += 1
        need(self.entries <= ENTRIES, 'aggregate-archive-entry-bound')
        target = self.target(row[0])
        if target is None: return
        if row[1] == 'directory':
            # Observed JDK GNU directory sgid is DATA, never installed authority.
            need(row[2] in (0o40755, 0o42755), 'unsupported-vendor-directory-mode')
            held, _ = self.parent(target + '/__directory_only__')
            close_chain(*held)
        elif row[1] == 'alias':
            # No implicit hardlink, alias chasing, or new link interpretation.
            raise Refused('unsupported-vendor-alias')
        else:
            need(row[1] == 'file', 'unsupported-vendor-entry')
        # Files remain0600 until every archive completely validates.

    def capture(self, role, opener):
        self.role = role
        self.point()
        endpoint = time.monotonic() + min(120, (self.clock.deadline - self.clock.check()) / 1e9)
        url = role['url']; response = None; fd = None
        target = self.work / 'archives' / role['role']
        held = chain(target.parent, retained=True); primary = None
        try:
            def request(address):
                need(time.monotonic() < endpoint, 'archive-download-deadline')
                req = urllib.request.Request(address, headers={'Accept-Encoding': 'identity', 'Connection': 'close'}, method='GET')
                try: return opener.open(req, timeout=max(.01, min(10, endpoint - time.monotonic())))
                except urllib.error.HTTPError as error: return error
            response = request(url); headers = P.response_headers(response)
            if url.startswith('https://github.com/'):
                need(response.code == 302, 'fixed-release-redirect')
                address = P.release_redirect(headers.get('location'))
                closing, response = response, None; closing.close()
                response = request(address); headers = P.response_headers(response)
            need(response.code == 200 and 'location' not in headers
                 and headers.get('content-encoding', 'identity') == 'identity'
                 and ('content-length' not in headers or int(headers['content-length']) == role['bytes']), 'archive-response')
            fd = os.open(target.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=held[0][-1])
            sha = hashlib.sha256(); count = 0
            while True:
                self.point(); need(time.monotonic() < endpoint, 'archive-download-deadline')
                amount = min(CHUNK, role['bytes'] - count + 1)
                # Reserve unknown read outcomes before transport entry; never refund exceptions.
                need(self.downloads + amount <= 512 << 20, 'download-aggregate-bound')
                self.downloads += amount
                data = response.read(amount)
                need(type(data) is bytes and len(data) <= amount, 'archive-response-bytes')
                self.downloads -= amount - len(data)
                count += len(data)
                need(count <= role['bytes'], 'archive-size-bound')
                if not data: break
                sha.update(data); view = memoryview(data)
                while view:
                    self.point(); n = os.write(fd, view); need(n > 0, 'archive-write-short'); view = view[n:]
            need(count == role['bytes'] and sha.hexdigest() == role['sha256'], 'archive-checksum')
            closing, response = response, None; closing.close()
            os.fsync(fd)
            self.archive_fd, self.archive_before, self.archive_path = fd, nine(os.fstat(fd)), target
            need(self.archive_before[5] == 1 and self.archive_before[6] == role['bytes']
                 and stat.S_IMODE(self.archive_before[2]) == 0o600, 'archive-original')
            capture = C.compile_archive(self, C.Pin(role['role'], role['bytes'], role['sha256']), observer=self)
            capture.consume_rows(self.terminal_row)
            self.verify_binding()
            recheck_chain(*held)
        except BaseException as error:
            primary = error; raise
        finally:
            failure = None
            if self.active is not None:
                active, self.active = self.active, None
                try: close_chain(*active[1], file_fd=active[0])
                except BaseException as error: failure = error
            if response is not None:
                closing, response = response, None
                try: closing.close()
                except BaseException:
                    if failure is None: failure = Refused('transport-close-unknown')
            self.archive_fd = None
            try: close_chain(*held, file_fd=fd)
            except BaseException as error:
                if failure is None: failure = error
            if primary is None and failure is not None: raise failure

    def project_sdk_metadata(self):
        for entry in SDK_METADATA:
            self.point()
            self.charge_read(entry['bytes']); self.charge_read(1)
            raw, _ = read(SOURCE / entry['path'], entry['bytes'], clock=self.clock)
            need((len(raw), digest(raw)) == (entry['bytes'], entry['sha256']), 'sdk-source-metadata-pin')
            need(self.writes + len(raw) <= TOOL_BYTES and self.files < FILES
                 and self.entries < ENTRIES, 'sdk-metadata-resource-bound')
            self.entries += 1
            held, leaf = self.parent(entry['target']); fd = None; primary = None
            try:
                fd = os.open(leaf, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=held[0][-1])
                initial = nine(os.fstat(fd))
                need(initial[3] == os.getuid() and initial[5] == 1 and initial[6] == 0
                     and stat.S_IMODE(initial[2]) == 0o600, 'sdk-metadata-original')
                view = memoryview(raw)
                while view:
                    self.point(); count = os.write(fd, view)
                    need(count > 0, 'sdk-metadata-write-short'); view = view[count:]
                self.writes += len(raw); os.fsync(fd)
                before = nine(os.fstat(fd)); self.charge_read(len(raw)); self.charge_read(1)
                need(os.pread(fd, len(raw), 0) == raw and not os.pread(fd, 1, len(raw))
                     and before[:6] == initial[:6] and before[6] == len(raw)
                     and nine(os.fstat(fd)) == before
                     == nine(os.stat(leaf, dir_fd=held[0][-1], follow_symlinks=False)), 'sdk-metadata-post')
                recheck_chain(*held)
                self.append_row({'path': entry['target'], 'bytes': len(raw), 'sha256': digest(raw),
                    'origin': entry['origin'], 'sourcePath': entry['path'], 'mode': 0o444,
                    'identity': list(before)})
            except BaseException as error:
                primary = error; raise
            finally:
                try: close_chain(*held, file_fd=fd)
                except BaseException:
                    if primary is None: raise

    def seal_sdk_root(self):
        # All file-parent operations are complete. Only the fixed SDK root changes.
        self.point(); held = chain(self.work / 'tools', retained=True)
        fd = None; primary = None
        try:
            fd = os.open('sdk', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=held[0][-1])
            before = nine(os.fstat(fd))
            need(list(before[:5]) == self.directories.get('sdk')
                 and before[:5] == nine(os.stat('sdk', dir_fd=held[0][-1], follow_symlinks=False))[:5]
                 and stat.S_ISDIR(before[2]) and stat.S_IMODE(before[2]) == 0o700
                 and before[3] == os.getuid(), 'sdk-seal-original')
            self.point(); os.fchmod(fd, 0o500); os.fsync(fd)
            after = nine(os.fstat(fd))
            need(after[:2] + after[3:5] == before[:2] + before[3:5]
                 and stat.S_ISDIR(after[2]) and stat.S_IMODE(after[2]) == 0o500
                 and after[:5] == nine(os.stat('sdk', dir_fd=held[0][-1], follow_symlinks=False))[:5],
                 'sdk-seal-post')
            recheck_chain(*held); self.point()
            self.directories['sdk'] = list(after[:5])
        except BaseException as error:
            primary = error; raise
        finally:
            try: close_chain(*held, file_fd=fd)
            except BaseException:
                if primary is None: raise

    def seal(self):
        need(self.files > 0 and len({r['path'] for r in self.roster}) == self.files, 'tool-roster')
        for row in self.roster:
            self.point()
            held, leaf = self.parent(row['path']); fd = None; primary = None
            try:
                fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=held[0][-1])
                need(list(nine(os.fstat(fd))) == row['identity'], 'tool-preseal-original')
                os.fchmod(fd, row['mode']); os.fsync(fd)
                after = nine(os.fstat(fd))
                need(nine(os.stat(leaf, dir_fd=held[0][-1], follow_symlinks=False)) == after
                     and stat.S_IMODE(after[2]) == row['mode'], 'tool-seal-post')
                row['identity'] = list(after)
                recheck_chain(*held)
            except BaseException as error:
                primary = error; raise
            finally:
                try: close_chain(*held, file_fd=fd)
                except BaseException:
                    if primary is None: raise
        aapt = next(r for r in self.roster if r['path'] == 'gradle/native/aapt2/aapt2')
        need((aapt['bytes'], aapt['sha256'], aapt['vendorMode']) == (11143368,
             '213e3d049e2c85daa930ed777bbd5627c1c5479a8d6698029b8f9c0161ad0a7e', 0o100755), 'osx-aapt2-member')
        self.seal_sdk_root()
        raw = encoded(self.roster); need(len(raw) <= 4 << 20, 'tool-roster-bound')
        directories = encoded(self.directories)
        need(len(directories) <= 4 << 20, 'directory-roster-bound')
        for body in (raw, directories):
            for at in range(0, len(body), CHUNK): self.charge_read(min(CHUNK, len(body) - at))
            self.charge_read(1)
        publish_preparation(self.work, 'tool-roster.json', raw, clock=self.clock)
        publish_preparation(self.work, 'directory-roster.json', directories, clock=self.clock)
        return digest(raw + directories)

def acquire(work, *, private=None):
    admit_b_nomination(B_DATA)
    # This flag selects the internal role; it is NOT parent authentication.
    need(os.environ.get('MRK_ANDROID_ACQUISITION_CHILD') == '1' and private is not None, 'acquisition-original-required')
    python_executable = observed_python_executable()
    a = Acquisition(work)
    recheck_chain(private['fds'], private['originals'])
    a.charge_read(16384); a.charge_read(1)
    sdk_sha = current_observation(work, a.clock)  # Current private original, SOURCE and reviewed cohort.
    for _ in range((1 << 20) // CHUNK): a.charge_read(CHUNK)
    a.charge_read(1)
    ca, ca_identity = read(Path('/private/etc/ssl/cert.pem'), 1 << 20, clock=a.clock)
    need(ca_identity[3] == 0, 'root-owned-stock-ca')
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.verify_mode = ssl.CERT_REQUIRED; tls.check_hostname = True
    tls.load_verify_locations(cadata=ca.decode('ascii'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), P.NoRedirect(), urllib.request.HTTPSHandler(context=tls))
    for row in ARCHIVES: a.capture(row, opener)
    a.project_sdk_metadata()
    roster_sha = a.seal()
    a.charge_read(16384); a.charge_read(1)  # Reserve fixed receipt readback before publication.
    publish_preparation(work, 'acquisition.json', encoded({'status': 'closed', 'phase': 'acquisition',
        'source': os.environ['GITHUB_SHA'], 'workflow': WORKFLOW, 'ref': REF, 'archives': ARCHIVES,
        'archiveBytes': 469391018, 'toolBytes': a.writes, 'readBytes': a.reads,
        'files': a.files, 'entries': a.entries, 'stockCaSha256': digest(ca),
        'sdkObservationSha256': sdk_sha, 'sdkMetadata': SDK_METADATA, 'toolRosterSha256': roster_sha,
        'nativeExecuted': False, 'protectedRegistration': False, 'pythonExecutable': python_executable,
        'phaseClock': a.clock.before_publication()}), clock=a.clock)
    recheck_chain(private['fds'], private['originals'])
    # main consumes its retained work descriptors before the final successful endpoint.
    return a.clock


def tool_post(work, clock):
    raw, _ = read(work / 'tool-roster.json', 4 << 20, clock=clock)
    rows = json.loads(raw); need(type(rows) is list and len(rows) <= FILES, 'tool-roster-shape')
    directories_raw, _ = read(work / 'directory-roster.json', 4 << 20, clock=clock)
    directories = json.loads(directories_raw)
    need(type(directories) is dict and len(directories) <= ENTRIES, 'directory-roster-shape')
    expected = {row['path'] for row in rows} | set(directories)
    found = set()
    for root, dirs, files in os.walk(work / 'tools', followlinks=False):
        clock.check()
        for name in dirs + files:
            path = Path(root) / name; relative = str(path.relative_to(work / 'tools'))
            if relative not in expected or relative in found:
                error = Refused('tool-namespace-changed')
                try:
                    # No body/stat/extra traversal. Only one exact public SOURCE
                    # cache name is reportable; unknown names remain hashes.
                    raw_relative = relative.encode('utf-8')
                    if 0 < len(raw_relative) <= 4096:
                        family = relative.split('/', 1)[0]
                        error.tool_namespace = {
                            'change': 'duplicate' if relative in found else 'unexpected',
                            'toolFamily': family if family in ('jdk', 'sdk', 'gradle') else 'other',
                            'relativeBytes': len(raw_relative), 'relativeSha256': digest(raw_relative),
                            'publicPath': relative if relative == 'sdk/.knownPackages' else None}
                except BaseException:
                    pass  # Optional diagnostics never replace the original refusal.
                raise error
            found.add(relative); need(len(found) <= ENTRIES + FILES, 'tool-namespace-bound')
            if relative in directories:
                need(list(nine(os.lstat(path))[:5]) == directories[relative], 'tool-directory-post')
    need(found == expected, 'tool-namespace-incomplete')
    total = 0
    for row in rows:
        clock.check(); total += row['bytes']; need(total <= TOOL_BYTES, 'tool-total')
        path = work / 'tools' / row['path']
        held = chain(path.parent, retained=True); fd = None; primary = None
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=held[0][-1])
            before = nine(os.fstat(fd)); need(list(before) == row['identity'], 'tool-identity')
            sha = hashlib.sha256()
            for at in range(0, row['bytes'], CHUNK):
                clock.check(); count = min(CHUNK, row['bytes'] - at); part = os.pread(fd, count, at)
                need(len(part) == count, 'tool-short'); sha.update(part)
            clock.check()
            need(not os.pread(fd, 1, row['bytes']) and sha.hexdigest() == row['sha256']
                 and nine(os.fstat(fd)) == before
                 == nine(os.stat(path.name, dir_fd=held[0][-1], follow_symlinks=False)), 'tool-post')
            recheck_chain(*held)
        except BaseException as error:
            primary = error; raise
        finally:
            try: close_chain(*held, file_fd=fd)
            except BaseException:
                if primary is None: raise
    return digest(raw + directories_raw)


def resources():
    bodies = {}
    for name, pin in RESOURCES.items():
        raw, _ = read(SOURCE / name, 128 << 10)
        need((len(raw), digest(raw)) == tuple(pin), 'fixture-resource-pin'); bodies[name] = raw
    return list(bodies.values())


def materialize(work, project_raw, verification, clock):
    value = json.loads(project_raw)
    need(set(value) == {'schemaVersion', 'files', 'stages'} and value['schemaVersion'] == 1
         and value['stages'] == {} and len(value['files']) == 9, 'fixture-resource-shape')
    originals = {}
    for relative, content in value['files'].items():
        need(relative.startswith('project/'), 'fixture-project-prefix')
        name = relative.removeprefix('project/'); P.relative(name)
        body = base64.b64decode(content, validate=True)
        path = work / 'run/project' / name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        publish_preparation(work, 'run/project/' + name, body, clock=clock); originals[name] = digest(body)
    need(sum(len(base64.b64decode(r)) for r in value['files'].values()) == 3962, 'fixture-decoded-bound')
    publish_preparation(work, 'run/project/gradle/verification-metadata.xml', verification, clock=clock)
    originals['gradle/verification-metadata.xml'] = digest(verification)
    return originals


def arguments(work):
    run = work / 'run'; tools = work / 'tools'; jdk = tools / 'jdk/temurin-17.jdk/Contents/Home'
    jvm = shlex.join(['-Xms64m', '-Xmx2048m', '-XX:MaxMetaspaceSize=512m', '-Dfile.encoding=UTF-8',
        '-Duser.home=' + str(run), '-Djava.io.tmpdir=' + str(run), '-Djna.nosys=true',
        '-Djna.boot.library.path=', '-Djna.boot.library.name=jnidispatch', '-Djna.tmpdir=' + str(run),
        '-Dorg.gradle.native.dir=' + str(run)])
    env = clean_environment(run)
    env.update(PATH=str(jdk / 'bin') + ':/usr/bin:/bin', JAVA_HOME=str(jdk),
        ANDROID_HOME=str(tools / 'sdk'), ANDROID_SDK_ROOT=str(tools / 'sdk'), XDG_RUNTIME_DIR=str(run),
        XDG_CONFIG_HOME=str(run / 'xdg-config'), XDG_CACHE_HOME=str(run / 'xdg-cache'),
        XDG_DATA_HOME=str(run / 'xdg-data'), XDG_STATE_HOME=str(run / 'xdg-state'),
        ANDROID_USER_HOME=str(run / 'android-user'), GRADLE_USER_HOME=str(run / 'gradle-home'),
        JAVA_OPTS=jvm, MOBILE_RELEASE_VERSION_NAME='1.2.3', MOBILE_RELEASE_BUILD_NUMBER='7',
        MOBILE_RELEASE_REQUIRE_SIGNING='false')
    command = ['/bin/sh', str(tools / 'gradle/bin/gradle'), '--no-daemon', '--no-watch-fs', '--no-parallel',
        '--console=plain', '--stacktrace', '--max-workers=2', '--project-cache-dir', str(run / 'project-cache'),
        '--gradle-user-home', str(run / 'gradle-home'), '-Dorg.gradle.jvmargs=' + jvm,
        '-Duser.home=' + str(run), '-Djava.io.tmpdir=' + str(run)]
    props = {'org.gradle.java.home': str(jdk), 'org.gradle.java.installations.paths': str(jdk),
        'org.gradle.java.installations.fromEnv': '', 'org.gradle.java.installations.auto-detect': 'false',
        'org.gradle.java.installations.auto-download': 'false', 'android.builder.sdkDownload': 'false',
        'android.aapt2FromMavenOverride': str(tools / 'gradle/native/aapt2/aapt2'),
        'kotlin.compiler.execution.strategy': 'in-process', 'kotlin.daemon.enabled': 'false'}
    for key, val in props.items():
        command += ['-D' + key + '=' + val, '-P' + key + '=' + val]
    command += ['--dependency-verification', 'strict', '--write-locks', ':app:bundleRelease']
    return env, command, jdk


def inventory(work, verification, clock):
    ns = {'v': 'https://schema.gradle.org/dependency-verification'}
    xml = ET.fromstring(verification); allowed = {}
    for component in xml.findall('v:components/v:component', ns):
        for artifact in component.findall('v:artifact', ns):
            key = (component.attrib['group'], component.attrib['name'], component.attrib['version'], artifact.attrib['name'])
            allowed[key] = artifact.find('v:sha256', ns).attrib['value']
    need(len(allowed) == 386, 'verification-roster')
    cache = work / 'run/gradle-home/caches/modules-2/files-2.1'
    rows = []; total = 0; count = 0
    for root, dirs, files in os.walk(cache, followlinks=False):
        clock.check(); count += len(dirs) + len(files); need(count <= 8192, 'maven-entry-bound')
        for name in dirs:
            s = os.lstat(Path(root) / name); need(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid(), 'maven-directory')
        for name in files:
            relative = (Path(root) / name).relative_to(cache).parts
            need(len(relative) == 5 and len(rows) < 1024, 'maven-roster-bound')
            size, sha, _ = file_digest(Path(root) / name, 64 << 20, clock)
            total += size; need(total <= MAVEN_BYTES, 'maven-byte-bound')
            key = (relative[0], relative[1], relative[2], relative[4])
            need(allowed.get(key) == sha, 'maven-unreviewed-artifact')
            rows.append({'group': key[0], 'name': key[1], 'version': key[2], 'artifact': key[3], 'bytes': size, 'sha256': sha})
    need(rows, 'maven-inventory-absent')
    return {'classification': 'actual-cache-artifacts-not-independent-task-resolution-graph',
            'locksAreOriginalGradleTaskOutputs': False, 'locksAreReviewedAInputs': True, 'rows': sorted(rows, key=lambda r: tuple(r.values()))}


def admit_a_locks(buildscript_raw, app_raw):
    """Pure Gradle8.14.5 lock DATA; neither genuine A nomination nor B admission.

    Return canonical per-file configuration states, preserving named-empty
    states. The caller still owns raw originals/pins and actual task coverage;
    lock text cannot prove the absence of an external changing-module flag.
    """
    need(type(buildscript_raw) is bytes and type(app_raw) is bytes
         and len(buildscript_raw) > 0 and len(app_raw) > 0
         and len(buildscript_raw) + len(app_raw) <= (32 << 10), 'a-locks-input-bound')
    headers = ('# This is a Gradle generated file for dependency locking.',
               '# Manual edits can break the build and are not advised.',
               '# This file is expected to be part of source control.')
    # Closed token policy for the fixed project, not every possible Gradle name.
    token = re.compile(r'[A-Za-z0-9_.-]+')

    def configurations(value, *, allow_empty=False):
        if allow_empty and value == '':
            return ()
        names = value.split(',')
        need(all(token.fullmatch(name) is not None for name in names), 'a-locks-configuration-token')
        need(len(set(names)) == len(names), 'a-locks-duplicate-configuration')
        return tuple(names)

    def states(raw):
        try:
            text = raw.decode('utf-8', 'strict').replace('\r\n', '\n')
        except UnicodeDecodeError:
            raise Refused('a-locks-utf8') from None
        need(all(char == '\n' or char.isprintable() for char in text), 'a-locks-text-control')
        lines = text.split('\n')
        need(tuple(lines[:3]) == headers, 'a-locks-header')
        by_configuration = {}; seen = set(); empty_names = None
        for line in lines[3:]:
            if not line or line.startswith('#'):
                continue
            need(line.count('=') == 1, 'a-locks-record-shape')
            coordinate, configured = line.split('=')
            if coordinate == 'empty':
                need(empty_names is None, 'a-locks-duplicate-empty-record')
                empty_names = configurations(configured, allow_empty=True)
                continue
            need(empty_names is None, 'a-locks-empty-record-order')
            gav = tuple(coordinate.split(':'))
            need(len(gav) == 3 and all(token.fullmatch(part) is not None for part in gav),
                 'a-locks-coordinate-token')
            group, artifact, version = gav
            need(not version.lower().startswith('latest.') and not version.upper().endswith('SNAPSHOT'),
                 'a-locks-nonfixed-version')
            need(gav not in seen, 'a-locks-duplicate-coordinate'); seen.add(gav)
            names = configurations(configured)
            for name in names:
                modules = by_configuration.setdefault(name, {})
                key = (group, artifact)
                need(key not in modules, 'a-locks-conflicting-module-state')
                modules[key] = version
        need(empty_names is not None, 'a-locks-missing-empty-record')
        for name in empty_names:
            need(name not in by_configuration, 'a-locks-empty-state-conflict')
            by_configuration[name] = {}
        need(by_configuration, 'a-locks-absent-configuration-state')
        return tuple((name, tuple((group, artifact, version)
                                  for (group, artifact), version in sorted(modules.items())))
                     for name, modules in sorted(by_configuration.items()))

    root_states, app_states = states(buildscript_raw), states(app_raw)
    need(('com.android.tools.build', 'gradle', '8.9.2') in dict(root_states).get('classpath', ()),
         'a-locks-required-root-agp-classpath')
    return root_states, app_states

def admit_a_inventory(raw, verification, verification_pin):
    """Pure bounded A DATA predicate; no nomination, SOURCE, filesystem or B role.

    The caller must separately admit the exact A artifact and review. This checks
    its inventory shape/content against an explicitly supplied reviewed XML pin;
    it does not turn cache rows into task-resolution edges or native evidence.
    """
    need(type(raw) is bytes and 0 < len(raw) <= 1 << 20, 'a-inventory-input-bound')
    need(type(verification_pin) in (tuple, list) and len(verification_pin) == 2
         and type(verification_pin[0]) is int and 0 < verification_pin[0] <= 128 << 10
         and type(verification_pin[1]) is str and re.fullmatch('[0-9a-f]{64}', verification_pin[1])
         and type(verification) is bytes and len(verification) == verification_pin[0]
         and digest(verification) == verification_pin[1],
         'a-inventory-verification-pin')
    # document() is intentionally not reused: its 64KiB limit is for small
    # receipts, while this independently bounded inventory admits up to 1MiB.
    value = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=N.pairs,
                       parse_constant=lambda _: need(False, 'a-inventory-nonfinite'))
    need(type(value) is dict and set(value) == {'classification', 'locksAreOriginalGradleTaskOutputs', 'rows'}
         and value['classification'] == 'actual-cache-artifacts-not-independent-task-resolution-graph'
         and value['locksAreOriginalGradleTaskOutputs'] is True, 'a-inventory-fields')
    ns = {'v': 'https://schema.gradle.org/dependency-verification'}
    xml = ET.fromstring(verification)
    need(xml.tag == '{' + ns['v'] + '}verification-metadata'
         and xml.findtext('v:configuration/v:verify-metadata', namespaces=ns) == 'true', 'a-inventory-xml-policy')
    allowed = {}; components = set()
    for component in xml.findall('v:components/v:component', ns):
        gav = tuple(component.attrib[key] for key in ('group', 'name', 'version'))
        need(gav not in components, 'a-inventory-xml-duplicate-component'); components.add(gav)
        for artifact in component.findall('v:artifact', ns):
            key = gav + (artifact.attrib['name'],)
            checksums = artifact.findall('v:sha256', ns)
            need(key not in allowed and len(checksums) == 1, 'a-inventory-xml-artifact')
            sha = checksums[0].attrib['value']
            need(re.fullmatch('[0-9a-f]{64}', sha) is not None, 'a-inventory-xml-sha256')
            allowed[key] = sha
    need(len(components) == 234 and len(allowed) == 386, 'a-inventory-xml-roster')
    need(type(value['rows']) is list and 0 < len(value['rows']) <= 1024, 'a-inventory-row-bound')
    rows = []; seen = set(); total = 0
    for row in value['rows']:
        need(type(row) is dict and set(row) == {'group', 'name', 'version', 'artifact', 'bytes', 'sha256'},
             'a-inventory-row-fields')
        need(all(type(row[key]) is str for key in ('group', 'name', 'version', 'artifact', 'sha256'))
             and type(row['bytes']) is int and 0 < row['bytes'] <= 64 << 20, 'a-inventory-row-types')
        key = tuple(row[field] for field in ('group', 'name', 'version', 'artifact'))
        need(key not in seen, 'a-inventory-duplicate-artifact'); seen.add(key)
        need(allowed.get(key) == row['sha256'], 'a-inventory-unreviewed-artifact')
        total += row['bytes']; need(total <= MAVEN_BYTES, 'a-inventory-byte-bound')
        rows.append(key + (row['bytes'], row['sha256']))
    return tuple(sorted(rows))

def admit_b_nomination(value):
    """Fixed reviewed-A nomination shape, not an artifact fetch or pass claim."""
    need(value is not None, 'b-data-not-nominated')
    fields = {'schemaVersion', 'source', 'tree', 'run', 'attempt', 'job', 'artifactId',
              'artifactSha256', 'reviewSha256', 'pythonExecutable', 'resources'}
    need(type(value) is dict and set(value) == fields and type(value['schemaVersion']) is int
         and value['schemaVersion'] == 1, 'b-nomination-fields')
    need(all(type(value[k]) is str and re.fullmatch('[0-9a-f]{40}', value[k]) for k in ('source', 'tree'))
         and all(type(value[k]) is str and re.fullmatch('[0-9a-f]{64}', value[k])
                 for k in ('artifactSha256', 'reviewSha256'))
         and all(type(value[k]) is int and 0 < value[k] < 1 << 63
                 for k in ('run', 'attempt', 'job', 'artifactId')), 'b-nomination-cohort')
    python = value['pythonExecutable']
    need(type(python) is str and 1 < len(python) <= 1024 and python.startswith('/')
         and all('!' <= char <= '~' for char in python)
         and all(part not in ('', '.', '..') for part in python.split('/')[1:]), 'b-nomination-python')
    need(type(value['resources']) is dict and set(value['resources']) == set(B_DATA_ROSTER), 'b-nomination-resources')
    for name, maximum in B_DATA_ROSTER.items():
        pin = value['resources'][name]
        need(type(pin) in (list, tuple) and len(pin) == 2 and type(pin[0]) is int and 0 < pin[0] <= maximum
             and type(pin[1]) is str and re.fullmatch('[0-9a-f]{64}', pin[1]), 'b-nomination-resource-pin')
    need(sum(value['resources'][name][0] for name in ('buildscript-gradle.lockfile', 'app-gradle.lockfile')) <= 32 << 10,
         'b-nomination-lock-bound')
    return value

def b_arguments(work):
    """Same fixed environment/tools/task, with no lock/update/checksum learning."""
    env, command, jdk = arguments(work)
    need(command[-4:] == ['--dependency-verification', 'strict', '--write-locks', ':app:bundleRelease'],
         'b-fixed-a-command-tail')
    need(command.count('--write-locks') == 1, 'b-fixed-a-write-flag')
    command = [arg for arg in command if arg != '--write-locks']
    need(not any(arg.startswith(('--write-locks', '--update-locks', '--write-verification-metadata')) for arg in command),
         'b-no-write-flags')
    return env, command, jdk

def admit_a_receipt(raw, nomination, project_raw, verification):
    """Old A context is explicit; never impersonate it with current globals."""
    nominated = admit_b_nomination(nomination)
    need(type(raw) is bytes and len(raw) == nominated['resources']['receipt.json'][0]
         and digest(raw) == nominated['resources']['receipt.json'][1], 'b-a-receipt-pin')
    value = N.document(raw)
    fields = {'schemaVersion', 'phase', 'status', 'source', 'workflow', 'ref', 'wrapperReturncodeRequired',
        'commands', 'sourcePrePost', 'toolRosterSha256', 'acquisitionSha256', 'acquisitionClock',
        'sdkObservationSha256', 'sdkMetadata', 'aab', 'fixtureSha256', 'verificationSha256',
        'workIdentity', 'disposalIdentities', 'protectedRegistration', 'uiQualification', 'phaseClock'}
    need(set(value) == fields and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
         and value['phase'] == 'A' and value['status'] == 'closed-awaiting-distinct-data-review'
         and value['source'] == nominated['source'] and value['workflow'] == WORKFLOW and value['ref'] == REF
         and value['sourcePrePost'] is True and type(value['wrapperReturncodeRequired']) is int
         and value['wrapperReturncodeRequired'] == 0 and value['protectedRegistration'] is False
         and value['uiQualification'] is False and value['sdkMetadata'] == SDK_METADATA, 'b-a-receipt-fields')
    need(value['fixtureSha256'] == digest(project_raw) and value['verificationSha256'] == digest(verification)
         and all(type(value[k]) is str and re.fullmatch('[0-9a-f]{64}', value[k])
                 for k in ('toolRosterSha256', 'acquisitionSha256', 'sdkObservationSha256')), 'b-a-receipt-source')
    clock_record(value['phaseClock'], PHASE_SECONDS); clock_record(value['acquisitionClock'], ACQUISITION_SECONDS)
    # The public A receipt does not expose its random private work path. Its
    # three vendor argv hashes remain pinned DATA for distinct A review, not
    # independently reconstructed argv. Fixed source/acquisition args are known.
    head = ['/usr/bin/git', '-C', str(SOURCE), 'rev-parse', 'HEAD']
    clean = ['/usr/bin/git', '-C', str(SOURCE), 'status', '--porcelain=v1', '--untracked-files=all']
    expected = [('source-head-pre', head, 10, 4096), ('source-clean-pre', clean, 10, 16384),
        ('android-public-tool-acquisition', [nominated['pythonExecutable'], '-I', '-S', '-B',
            str(SOURCE / 'desktop/tools/macos_android_dependency_preparation.py'), 'acquire'], 840, 16384),
        ('android-dependency-jdk-version', None, 15, 8192),
        ('android-dependency-gradle-version', None, 15, 8192),
        ('android-dependency-lock-task', None, 900, 2 << 20),
        ('source-head-post', head, 10, 4096), ('source-clean-post', clean, 10, 16384)]
    need(type(value['commands']) is list and len(value['commands']) == len(expected), 'b-a-command-count')
    for record, (role, argv, cap, limit) in zip(value['commands'], expected):
        need(type(record) is dict and set(record) == {'role', 'returncode', 'timeoutSeconds', 'roleCapSeconds',
             'outputLimitBytes', 'argvSha256', 'stdoutBytes', 'stdoutSha256', 'stderrBytes', 'stderrSha256'}, 'b-a-command-fields')
        need(record['role'] == role and type(record['returncode']) is int and record['returncode'] == 0
             and type(record['roleCapSeconds']) is int and record['roleCapSeconds'] == cap
             and type(record['timeoutSeconds']) is int and 1 <= record['timeoutSeconds'] <= cap
             and type(record['outputLimitBytes']) is int and record['outputLimitBytes'] == limit
             and type(record['argvSha256']) is str and re.fullmatch('[0-9a-f]{64}', record['argvSha256'])
             and (argv is None or record['argvSha256'] == digest(N.encoded(argv))), 'b-a-command-original')
        need(all(type(record[k]) is int and 0 <= record[k] <= limit for k in ('stdoutBytes', 'stderrBytes'))
             and record['stdoutBytes'] + record['stderrBytes'] <= limit
             and all(type(record[k]) is str and re.fullmatch('[0-9a-f]{64}', record[k])
                     for k in ('stdoutSha256', 'stderrSha256')), 'b-a-command-output')
        if role.startswith('source-'):
            body = (nominated['source'] + '\n').encode() if 'head' in role else b''
            need(record['stdoutBytes'] == len(body) and record['stdoutSha256'] == digest(body)
                 and record['stderrBytes'] == 0 and record['stderrSha256'] == digest(b''), 'b-a-source-command')
    need(type(value['aab']) is dict and set(value['aab']) == {'bytes', 'sha256'}
         and type(value['aab']['bytes']) is int and 0 < value['aab']['bytes'] <= 64 << 20
         and type(value['aab']['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['aab']['sha256']), 'b-a-aab')
    need(type(value['disposalIdentities']) is dict and set(value['disposalIdentities']) == {'archives', 'tools', 'run'}, 'b-a-identities')
    for identity in [value['workIdentity'], *value['disposalIdentities'].values()]:
        need(type(identity) is list and len(identity) == 5 and all(type(v) is int and v >= 0 for v in identity)
             and stat.S_ISDIR(identity[2]) and stat.S_IMODE(identity[2]) == 0o700, 'b-a-identity-shape')
    # These are historical DATA only. Do not compare with a current B inode/uid.
    return value

def read_b_inputs(source, nomination, project_raw, verification, verification_pin, clock):
    nominated = admit_b_nomination(nomination)  # Absent prerequisite before any read/network/tool.
    bodies = {}; originals = {}
    for name in B_DATA_ROSTER:
        raw, identity = read(source / 'desktop/tools/android_dependency_preparation_data/phase-a' / name,
                             nominated['resources'][name][0], clock=clock)
        need((len(raw), digest(raw)) == tuple(nominated['resources'][name]), 'b-input-original-pin')
        bodies[name] = raw; originals[name] = identity
    receipt = admit_a_receipt(bodies['receipt.json'], nominated, project_raw, verification)
    rows = admit_a_inventory(bodies['inventory.json'], verification, verification_pin)
    # The separately reviewed pure parser preserves named-empty configurations;
    # only the fixed reviewed A nomination permits these DATA into replay.
    locks = admit_a_locks(bodies['buildscript-gradle.lockfile'], bodies['app-gradle.lockfile'])
    ns = {'v': 'https://schema.gradle.org/dependency-verification'}
    allowed = {tuple(node.attrib[k] for k in ('group', 'name', 'version'))
               for node in ET.fromstring(verification).findall('v:components/v:component', ns)}
    need(all(gav in allowed for file_states in locks for _, gavs in file_states for gav in gavs),
         'b-lock-unreviewed-coordinate')
    clock.check()
    return {'nomination': nominated, 'raw': bodies, 'originals': originals,
            'receipt': receipt, 'inventoryRows': rows, 'lockStates': locks}

def b_input_post(source, inputs, clock):
    nominated = admit_b_nomination(inputs['nomination'])
    need(set(inputs['raw']) == set(inputs['originals']) == set(B_DATA_ROSTER), 'b-input-original-roster')
    for name in B_DATA_ROSTER:
        raw, identity = read(source / 'desktop/tools/android_dependency_preparation_data/phase-a' / name,
                             nominated['resources'][name][0], clock=clock)
        need(identity == inputs['originals'][name] and raw == inputs['raw'][name]
             and (len(raw), digest(raw)) == tuple(nominated['resources'][name]), 'b-input-original-post')

def b_materialize_locks(work, inputs, clock):
    nominated = admit_b_nomination(inputs['nomination']); originals = {}
    for resource, relative in (('buildscript-gradle.lockfile', 'buildscript-gradle.lockfile'),
                               ('app-gradle.lockfile', 'app/gradle.lockfile')):
        raw = inputs['raw'][resource]
        need(type(raw) is bytes and len(raw) == nominated['resources'][resource][0]
             and digest(raw) == nominated['resources'][resource][1], 'b-lock-input-pin')
        publish_preparation(work, 'run/project/' + relative, raw, clock=clock)
        actual, identity = read(work / 'run/project' / relative, 32 << 10, clock=clock)
        need(actual == raw, 'b-lock-materialized-readback'); originals[relative] = (identity, digest(raw))
    return originals

def b_lock_post(work, originals, clock):
    need(type(originals) is dict and set(originals) == {'buildscript-gradle.lockfile', 'app/gradle.lockfile'},
         'b-lock-post-roster')
    records = []
    for relative, record in originals.items():
        need(type(record) in (tuple, list) and len(record) == 2, 'b-lock-post-record')
        before, sha = record
        need(type(before) in (tuple, list) and len(before) == 9
             and all(type(value) is int and value >= 0 for value in before)
             and stat.S_ISREG(before[2]) and before[5] == 1 and 0 < before[6] <= 32 << 10
             and type(sha) is str and re.fullmatch('[0-9a-f]{64}', sha), 'b-lock-post-original')
        records.append((relative, tuple(before), sha))
    need(sum(before[6] for _, before, _ in records) <= 32 << 10, 'b-lock-post-combined-bound')
    for relative, before, sha in records:
        raw, identity = read(work / 'run/project' / relative, 32 << 10, clock=clock)
        need(identity == before and digest(raw) == sha, 'b-lock-original-post')

def b_inventory_document(inputs):
    fields = ('group', 'name', 'version', 'artifact', 'bytes', 'sha256')
    return {'classification': 'actual-cache-artifacts-not-independent-task-resolution-graph',
            'locksAreOriginalGradleTaskOutputs': False, 'locksAreReviewedAInputs': True,
            'rows': [dict(zip(fields, row)) for row in inputs['inventoryRows']]}


def b_input_statement(nomination):
    nominated = admit_b_nomination(nomination)
    return {'aSource': nominated['source'], 'aTree': nominated['tree'], 'aRun': nominated['run'],
            'aAttempt': nominated['attempt'], 'aJob': nominated['job'], 'aArtifactId': nominated['artifactId'],
            'aArtifactSha256': nominated['artifactSha256'], 'aReviewSha256': nominated['reviewSha256'],
            'aInputs': nominated['resources'], 'locksAreReviewedAInputs': True,
            'locksAreOriginalGradleTaskOutputs': False}


def gradle_failure_projection(stderr, work, project_raw, verification, *, stdout=b'', clock=None):
    """Closed public facts from both returned streams; never arbitrary message text."""
    need(type(stderr) is bytes and type(stdout) is bytes and len(stderr) + len(stdout) <= 2 << 20,
         'gradle-diagnostic-input-bound')
    for raw, name in ((project_raw, 'project-v1.json'), (verification, 'verification-v1.xml')):
        need(type(raw) is bytes and (len(raw), digest(raw)) == tuple(RESOURCES[
            'desktop/tools/android_dependency_preparation_data/' + name]), 'gradle-diagnostic-public-source')
    project = json.loads(project_raw)
    sources = {}
    for relative in ('build.gradle', 'settings.gradle', 'app/build.gradle',
                     'app/src/main/java/org/example/saved/MainActivity.java'):
        body = base64.b64decode(project['files']['project/' + relative], validate=True).decode('utf-8')
        sources[relative] = body.splitlines()
    ns = {'v': 'https://schema.gradle.org/dependency-verification'}
    xml = ET.fromstring(verification)
    coordinates = {':'.join(node.attrib[k] for k in ('group', 'name', 'version'))
                   for node in xml.findall('v:components/v:component', ns)}
    need(0 < len(coordinates) <= 386, 'gradle-diagnostic-public-coordinates')
    classes = {
        'org.gradle.api.GradleException', 'org.gradle.api.GradleScriptException',
        'org.gradle.api.ProjectConfigurationException', 'org.gradle.api.InvalidUserCodeException',
        'org.gradle.api.InvalidUserDataException', 'org.gradle.api.UnknownProjectException',
        'org.gradle.api.UnknownTaskException', 'org.gradle.api.tasks.TaskExecutionException',
        'org.gradle.api.internal.tasks.TaskDependencyResolveException',
        'org.gradle.api.internal.tasks.compile.CompilationFailedException',
        'org.gradle.api.internal.plugins.PluginApplicationException',
        'org.gradle.api.internal.artifacts.ivyservice.TypedResolveException',
        'org.gradle.api.internal.artifacts.ivyservice.DefaultLenientConfiguration$ArtifactResolveException',
        'org.gradle.api.internal.artifacts.verification.exceptions.DependencyVerificationException',
        'org.gradle.internal.exceptions.LocationAwareException',
        'org.gradle.groovy.scripts.ScriptCompilationException',
        'org.gradle.internal.locking.LockOutOfDateException',
        'org.gradle.internal.resolve.ModuleVersionResolveException',
        'org.gradle.internal.resolve.ModuleVersionNotFoundException',
        'org.gradle.internal.resolve.ArtifactResolveException',
        'org.gradle.internal.resource.ResourceException',
        'org.gradle.internal.resource.transport.http.HttpErrorStatusCodeException',
        'org.gradle.process.internal.ExecException', 'com.android.builder.errors.EvalIssueException',
        'com.android.builder.internal.aapt.v2.Aapt2Exception',
        'com.android.builder.internal.aapt.v2.Aapt2InternalException',
        'org.codehaus.groovy.control.MultipleCompilationErrorsException',
        'groovy.lang.MissingPropertyException', 'groovy.lang.MissingMethodException', 'groovy.lang.GroovyRuntimeException',
        'org.gradle.internal.metaobject.AbstractDynamicObject$CustomMessageMissingMethodException',
        'org.gradle.internal.metaobject.AbstractDynamicObject$CustomMessageMissingPropertyException',
        'com.android.builder.sdk.LicenceNotAcceptedException', 'com.android.builder.sdk.InstallFailedException',
        'java.lang.IllegalArgumentException', 'java.lang.IllegalStateException',
        'java.lang.NoClassDefFoundError', 'java.lang.ClassNotFoundException',
        'java.lang.UnsupportedClassVersionError', 'java.lang.OutOfMemoryError',
        'java.io.IOException', 'java.io.FileNotFoundException',
        'java.net.UnknownHostException', 'java.net.ConnectException', 'java.net.SocketTimeoutException',
        'javax.net.ssl.SSLException', 'javax.net.ssl.SSLHandshakeException',
        'java.security.cert.CertificateException', 'java.security.cert.CertPathValidatorException',
        'sun.security.provider.certpath.SunCertPathBuilderException'}
    def public_class(value):
        # Namespace syntax is bounded context, not independent origin proof.
        return len(value) <= 221 and re.fullmatch(
            r'(?:org[.]gradle|com[.]android|java|javax|groovy|org[.]codehaus[.]groovy)'
            r'(?:[.][A-Za-z_$][A-Za-z0-9_$]{0,63}){1,12}', value) is not None
    symbols = {
        'HardcodedDebugMode',
        'JdkImageTransform', 'android.useAndroidX', 'android.enableJetifier',
        'core-for-system-modules.jar', 'javaCompiler', 'jlink',
        'dependencyVerificationMode', 'DependencyVerificationMode', 'LockMode', 'RepositoriesMode',
        'org.gradle.api.artifacts.dsl.LockMode', 'org.gradle.api.artifacts.verification.DependencyVerificationMode',
        'org.gradle.api.initialization.resolve.RepositoriesMode', 'STRICT', 'FAIL_ON_PROJECT_REPOS',
        'dependencyResolutionManagement', 'repositoriesMode', 'repositories', 'maven', 'url', 'uri',
        'dependencyLocking', 'lockAllConfigurations', 'lockMode', 'configurations', 'classpath',
        'resolutionStrategy', 'activateDependencyLocking', 'failOnDynamicVersions', 'failOnChangingVersions',
        'allprojects', 'configureEach', 'android', 'namespace', 'compileSdk', 'buildToolsVersion',
        'defaultConfig', 'applicationId', 'minSdk', 'targetSdk', 'versionCode', 'versionName',
        'compileOptions', 'sourceCompatibility', 'targetCompatibility', 'buildFeatures', 'buildConfig',
        'buildTypes', 'release', 'minifyEnabled', 'debuggable', 'JavaVersion', 'VERSION_17',
        'android.aapt2FromMavenOverride', 'android.builder.sdkDownload', 'org.gradle.java.home',
        'com.android.application', ':classpath', ':app', ':app:bundleRelease',
        ':app:releaseCompileClasspath', ':app:releaseRuntimeClasspath',
        ':app:compileReleaseJavaWithJavac', ':app:processReleaseResources', ':app:packageReleaseBundle'}
    templates = (
        ('execution failed for task', 'task-execution-failed'),
        ('read-only file system', 'filesystem-read-only'),
        ('cannot run program', 'executable-launch-failed'),
        ('bad cpu type', 'executable-cpu-unsupported'),
        ('no such file or directory', 'filesystem-entry-missing'),
        ('jdkimagetransform', 'jdk-image-transform-mentioned'),
        ('android.useandroidx', 'androidx-property-mentioned'),
        ('license for package', 'sdk-license-mentioned'),
        ('licenses have not been accepted', 'sdk-license-not-accepted'),
        ('a problem was found with the configuration of task', 'task-configuration-invalid'),
        ('problems were found with the configuration of task', 'task-configuration-invalid'),
        ('a problem occurred evaluating', 'script-evaluation-failed'),
        ('a problem occurred configuring', 'project-configuration-failed'),
        ('could not compile', 'script-compilation-failed'),
        ('startup failed:', 'script-startup-failed'),
        ('unable to resolve class', 'api-class-resolution-failed'),
        ('could not find method', 'api-method-resolution-failed'),
        ('could not get unknown property', 'api-property-read-failed'),
        ('could not set unknown property', 'api-property-write-failed'),
        ('no signature of method', 'api-method-signature-failed'),
        ('no such property:', 'api-property-missing'),
        ('plugin with id', 'plugin-id-mentioned'),
        ('was configured to prefer settings repositories', 'repository-policy-conflict'),
        ('dependency verification failed', 'dependency-verification-failed'),
        ('checksum', 'dependency-checksum-mentioned'),
        ('dependency lock state', 'dependency-lock-state-mentioned'),
        ('lock state is out of date', 'dependency-lock-state-outdated'),
        ('could not resolve', 'dependency-resolution-failed'),
        ('could not find', 'requested-item-not-found'),
        ('sdk location not found', 'sdk-location-not-found'),
        ('failed to find build tools revision', 'sdk-build-tools-missing'),
        ('failed to find platform sdk', 'sdk-platform-missing'),
        ('aapt2 daemon startup failed', 'aapt2-startup-failed'),
        ('android resource linking failed', 'android-resource-link-failed'),
        ('compilation failed', 'compilation-failed'),
        ('pkix path building failed', 'tls-certification-path-failed'),
        ('unable to find valid certification path', 'tls-certification-path-missing'),
        ('handshake_failure', 'tls-handshake-failed'),
        ('remote host terminated the handshake', 'tls-handshake-terminated'),
        ('could not get resource', 'network-resource-get-failed'),
        ("could not get 'http", 'network-get-failed'), ("could not head 'http", 'network-head-failed'),
        ('read timed out', 'network-read-timeout'), ('connect timed out', 'network-connect-timeout'),
        ('connection refused', 'network-connection-refused'),
        ('no space left on device', 'disk-space-exhausted'), ('too many open files', 'file-descriptors-exhausted'),
        ('java heap space', 'java-heap-exhausted'), ('gc overhead limit exceeded', 'java-gc-limit'),
        ('cannot allocate memory', 'memory-allocation-failed'),
        ('permission denied', 'filesystem-permission-denied'), ('operation not permitted', 'operation-not-permitted'))
    report = {'schemaVersion': 1, 'classification': 'bounded-public-gradle-failure-projection-not-rootcause-proof',
        'stderrBytes': len(stderr), 'stderrSha256': digest(stderr),
        'stdoutBytes': len(stdout), 'stdoutSha256': digest(stdout), 'sections': [], 'causes': [], 'tasks': [], 'frames': [],
        'facts': [], 'locations': [], 'modules': [], 'symbols': [], 'repositories': [],
        'scan': {'lines': 0, 'longLines': 0, 'invalidLines': 0, 'unknownCauses': 0,
                 'inputTruncated': False, 'factsTruncated': False, 'streamLines': {'stderr': 0, 'stdout': 0}}}
    limits = {'sections': 4, 'causes': 16, 'facts': 32, 'locations': 8, 'modules': 8, 'symbols': 16, 'repositories': 2, 'tasks': 8, 'frames': 4}
    def trim():
        # Never discard all recognized detail merely because optional fields
        # saturate. Preserve deepest causes/frames and actual failure markers.
        while len(encoded(report)) > (12 << 10) - 512:
            report['scan']['factsTruncated'] = True
            for optional in ('symbols', 'repositories', 'modules', 'locations', 'facts', 'sections', 'tasks', 'frames', 'causes'):
                if report[optional]:
                    report[optional].pop(0); break
            else: raise Refused('gradle-diagnostic-output-bound')
    def add(key, item):
        if item in report[key]: return
        if len(report[key]) == limits[key]:
            report['scan']['factsTruncated'] = True
            if key in ('causes', 'frames'): report[key].pop(0)  # Keep deepest public context.
            else: return
        report[key].append(item)
        trim()
    cause_index = 0
    section_names = {'* Where:': 'where', '* What went wrong:': 'what-went-wrong',
                     '* Exception is:': 'exception', '* Try:': 'try'}
    for stream, body in (('stderr', stderr), ('stdout', stdout)):
        section = 'unspecified'; at = 0; frame_slots = 0
        while at < len(body) and report['scan']['lines'] < 4096:
            if clock: clock.check()
            end = body.find(b'\n', at)
            if end < 0: end = len(body)
            length = end - at; start = at; at = min(end + 1, len(body))
            report['scan']['lines'] += 1; report['scan']['streamLines'][stream] += 1
            if length > 4096:
                report['scan']['longLines'] += 1; frame_slots = 0; continue
            raw = body[start:end].rstrip(b'\r')
            if any(byte < 32 and byte != 9 for byte in raw):
                report['scan']['invalidLines'] += 1; frame_slots = 0; continue
            try: line = raw.decode('utf-8', 'strict')
            except UnicodeError:
                report['scan']['invalidLines'] += 1; frame_slots = 0; continue
            stripped = line.strip()
            if stripped in section_names:
                section = section_names[stripped]; add('sections', section); frame_slots = 0; continue
            cause = re.match(r'^(?:Caused by:\s*)?([A-Za-z_$][A-Za-z0-9_.$]{0,220})(?::|$)', stripped)
            if cause and '.' in cause[1]:
                cause_index += 1; frame_slots = 0
                if cause[1] in classes or public_class(cause[1]):
                    add('causes', {'index': cause_index, 'class': cause[1], 'section': section, 'stream': stream})
                    frame_slots = 2
                else: report['scan']['unknownCauses'] += 1
            elif frame_slots:
                frame = re.fullmatch(r'at ([A-Za-z_$][A-Za-z0-9_.$]{0,220})[.]'
                    r'([A-Za-z_$][A-Za-z0-9_$]{0,63}|<init>|<clinit>)[(]'
                    r'([A-Za-z_$][A-Za-z0-9_$]{0,95}[.](?:java|kt|groovy)):([1-9][0-9]{0,5})[)]', stripped)
                if frame and public_class(frame[1]):
                    add('frames', {'causeIndex': cause_index, 'class': frame[1], 'method': frame[2],
                                   'file': frame[3], 'line': int(frame[4]), 'stream': stream})
                    frame_slots -= 1
                else: frame_slots = 0
            if stream == 'stderr':
                task = re.fullmatch(r"Execution failed for task '(:app:[A-Za-z_$][A-Za-z0-9_$]{0,95})'[.]", stripped)
                marker = 'task-execution-failed'
            else:
                task = re.fullmatch(r'> Task (:app:[A-Za-z_$][A-Za-z0-9_$]{0,95}) FAILED', stripped)
                marker = 'task-output-failed'
            if task: add('tasks', {'task': task[1], 'stream': stream, 'marker': marker})
            lowered = line.lower()
            for token, code in templates:
                if token in lowered: add('facts', code)
            http = re.search(r'Received status code (400|401|403|404|408|429|500|502|503|504)(?![0-9])', line)
            if http: add('facts', 'http-' + http[1])
            for host, label in (('dl.google.com', 'google-maven'), ('repo.maven.apache.org', 'maven-central')):
                if re.search(r'(?<![A-Za-z0-9.-])' + re.escape(host) + r'(?![A-Za-z0-9.-])', line): add('repositories', label)
            for symbol in sorted(symbols):
                if re.search(r'(?<![A-Za-z0-9_.$:-])' + re.escape(symbol) + r'(?![A-Za-z0-9_.$:-])', line):
                    add('symbols', symbol)
            for module in re.finditer(r'(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{1,100}:[A-Za-z0-9_.-]{1,100}:[A-Za-z0-9_.+-]{1,80})(?![A-Za-z0-9_.+-])', line):
                coordinate = module[1].rstrip('.')
                if coordinate in coordinates:
                    fact = 'could-not-resolve' if 'could not resolve' in lowered else 'could-not-find' if 'could not find' in lowered else 'mentioned'
                    add('modules', {'coordinate': coordinate, 'fact': fact})
            for relative, source_lines in sources.items():
                absolute = str(work / 'run/project' / relative)
                location = re.search(r'(?<![A-Za-z0-9_./-])' + re.escape(absolute) + r"(?:['\"] line: |:)([0-9]{1,5})(?![0-9])", line)
                if location:
                    number = int(location[1])
                    if 1 <= number <= len(source_lines):
                        public = source_lines[number - 1]
                        add('locations', {'file': 'project/' + relative, 'line': number,
                                          'sourceLine': public[:192], 'sourceLineTruncated': len(public) > 192})
        if at < len(body): report['scan']['inputTruncated'] = True
    report['recognition'] = 'recognized-public-facts' if any(report[k] for k in ('causes', 'frames', 'tasks', 'facts', 'locations', 'modules', 'symbols')) else 'no-allowlisted-detail'
    trim()  # Final counter/recognition changes share the same aggregate bound.
    need(len(encoded(report)) <= (12 << 10) - 512, 'gradle-diagnostic-output-bound')
    return report


def publish_gradle_failure(work, result, project_raw, verification, clock):
    """Failure-only diagnostic; caller still raises its original task refusal."""
    try:
        value = gradle_failure_projection(result.stderr, work, project_raw, verification, stdout=result.stdout, clock=clock)
    except BaseException:
        value = {'schemaVersion': 1, 'classification': 'bounded-public-gradle-failure-projection-not-rootcause-proof',
                 'recognition': 'projection-unavailable', 'stderrBytes': len(result.stderr),
                 'stderrSha256': digest(result.stderr), 'stdoutBytes': len(result.stdout),
                 'stdoutSha256': digest(result.stdout)}
    value.update(source=os.environ['GITHUB_SHA'], role='android-dependency-locked-task',
                 originalReturncode=result.returncode, originalTaskSuccess=False)
    try: publish_preparation(work, 'evidence/gradle-failure.json', encoded(value), clock=clock)
    except BaseException: pass  # Never mask the original task failure or reopen unknown output.


def source_original(phase, suffix):
    value = phase.call('source-head-' + suffix, ['/usr/bin/git', '-C', str(SOURCE), 'rev-parse', 'HEAD'], 10, 4096)
    need(value.returncode == 0 and value.stdout == (os.environ['GITHUB_SHA'] + '\n').encode(), 'source-head')
    value = phase.call('source-clean-' + suffix, ['/usr/bin/git', '-C', str(SOURCE), 'status', '--porcelain=v1', '--untracked-files=all'], 10, 16384)
    need(value.returncode == 0 and value.stdout == b'', 'source-clean')


def prepare(work, *, private=None):
    nominated = admit_b_nomination(B_DATA)  # Before SDK, reads, acquisition or vendor execution.
    need(os.statvfs(work).f_bavail * os.statvfs(work).f_frsize >= 8 << 30, 'eight-gib-free-prerequisite')
    admission_clock = N.PhaseClock(30)
    try:
        project_raw, verification = resources()
        inputs = read_b_inputs(SOURCE, nominated, project_raw, verification,
            RESOURCES['desktop/tools/android_dependency_preparation_data/verification-v1.xml'], admission_clock)
    except BaseException:
        # Input originals close inside read(). Preserve the first failure, and
        # terminate this same endpoint rather than starting an SDK allowance.
        try: admission_clock.finish()
        except BaseException: pass
        admission_clock.failed = True
        raise
    # Observation consumes the same endpoint on success; never finish it twice.
    observed_sdk = observe_sdk_current_use(work, private=private, clock=admission_clock)
    admit_sdk_current_use(observed_sdk)  # Refuses BEFORE download/materialization/native task.
    owner = N.load_normal_owner(SOURCE)
    for name in ('archives', 'tools', 'run', 'evidence'):
        os.mkdir(work / name, 0o700)
    identities = {name: list(nine(os.lstat(work / name))[:5]) for name in ('archives', 'tools', 'run')}
    root_identity = list(nine(os.lstat(work))[:5])
    clock = N.PhaseClock(ACQUISITION_SECONDS)
    child_env = clean_environment(work)
    for key in ('GITHUB_REPOSITORY', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'GITHUB_SHA', 'GITHUB_WORKFLOW_SHA',
                'GITHUB_WORKFLOW_REF', 'GITHUB_WORKSPACE', 'RUNNER_ENVIRONMENT', 'RUNNER_OS', 'RUNNER_ARCH', 'MRK_ANDROID_PREPARATION_WORK'):
        child_env[key] = os.environ[key]
    child_env['MRK_ANDROID_ACQUISITION_CHILD'] = '1'
    acquisition = N.NormalPhase(owner, child_env, SOURCE, clock)
    primary = None
    try:
        source_original(acquisition, 'pre')
        result = acquisition.call('android-public-tool-acquisition', [sys.executable, '-I', '-S', '-B',
            str(SOURCE / 'desktop/tools/macos_android_dependency_preparation.py'), 'acquire'], 840, 16384)
    except BaseException as error:
        primary = error; raise
    finally:
        try: publish_preparation(work, 'evidence/acquisition-commands.json', encoded(acquisition.records),
                                 clock=clock if primary is None else None)
        except BaseException:
            if primary is None: raise
    need(result.returncode == 0, 'acquisition-original-return')
    acquired, acquisition_sha = acquisition_receipt(work, clock)
    acquisition_clock = clock.before_publication()
    clock.finish()
    clock = N.PhaseClock(PHASE_SECONDS)
    originals = materialize(work, project_raw, verification, clock)
    lock_originals = b_materialize_locks(work, inputs, clock)
    b_input_post(SOURCE, inputs, clock); b_lock_post(work, lock_originals, clock)
    before_tools = tool_post(work, clock)
    need(before_tools == acquired['toolRosterSha256'], 'acquisition-live-tool-roster')
    env, command, jdk = b_arguments(work)
    phase = N.NormalPhase(owner, env, work / 'run/project', clock)
    try:
        for role, argv in [('android-dependency-jdk-version', [str(jdk / 'bin/java'), '-version']),
                           ('android-dependency-gradle-version', ['/bin/sh', str(work / 'tools/gradle/bin/gradle'), '--version'])]:
            result = phase.call(role, argv, 15, 8192); need(result.returncode == 0, 'tool-version-original-return')
        result = phase.call('android-dependency-locked-task', command, 900, 2 << 20)
        if result.returncode != 0:
            try: publish_gradle_failure(work, result, project_raw, verification, clock)
            except BaseException: pass  # Even diagnostic interruption cannot replace the actual task refusal.
        need(result.returncode == 0, 'gradle-original-return')
        b_lock_post(work, lock_originals, clock); b_input_post(SOURCE, inputs, clock)
        actual = inventory(work, verification, clock)
        if actual != b_inventory_document(inputs):
            # Only checksum-admitted public Maven metadata, never private cache
            # paths or tool output. Diagnostic failure cannot replace the drift.
            try:
                publish_preparation(work, 'evidence/inventory-drift.json', encoded({
                    'status': 'refused', 'reason': 'b-inventory-drift',
                    'source': os.environ['GITHUB_SHA'], 'inventory': actual}), clock=clock)
            except BaseException: pass
        need(actual == b_inventory_document(inputs), 'b-inventory-drift')
        locks = {'buildscript-gradle.lockfile': inputs['raw']['buildscript-gradle.lockfile'],
                 'app/gradle.lockfile': inputs['raw']['app-gradle.lockfile']}
        aab_size, aab_sha, prefix = file_digest(work / 'run/project/app/build/outputs/bundle/release/app-release.aab', 64 << 20, clock)
        need(prefix == b'PK\x03\x04', 'actual-aab-required')
        for name, sha in originals.items():
            raw, _ = read(work / 'run/project' / name, 128 << 10, clock=clock)
            need(digest(raw) == sha, 'project-source-post')
        source_original(phase, 'post')
        need(tool_post(work, clock) == before_tools and resources() == [project_raw, verification], 'source-tools-post')
        b_lock_post(work, lock_originals, clock); b_input_post(SOURCE, inputs, clock)
        publish_preparation(work, 'evidence/inventory.json', encoded(actual), clock=clock)
        for name, raw in locks.items():
            publish_preparation(work, 'evidence/' + name.replace('/', '-'), raw, clock=clock)
        receipt = {'schemaVersion': 1, 'phase': 'B', 'status': 'closed-awaiting-distinct-b-data-review',
            'source': os.environ['GITHUB_SHA'], 'workflow': WORKFLOW, 'ref': REF,
            'wrapperReturncodeRequired': 0, 'commands': acquisition.records + phase.records,
            'sourcePrePost': True, 'toolRosterSha256': before_tools,
            'aInputStatement': b_input_statement(nominated),
            'aInputOriginals': {name: list(identity) for name, identity in inputs['originals'].items()},
            'lockOriginals': lock_originals, 'inventorySha256': digest(encoded(actual)),
            'acquisitionSha256': acquisition_sha, 'acquisitionClock': acquisition_clock,
            'sdkObservationSha256': acquired['sdkObservationSha256'], 'sdkMetadata': SDK_METADATA,
            'aab': {'bytes': aab_size, 'sha256': aab_sha}, 'fixtureSha256': digest(project_raw),
            'verificationSha256': digest(verification), 'workIdentity': root_identity,
            'disposalIdentities': identities, 'protectedRegistration': False, 'uiQualification': False,
            'phaseClock': clock.before_publication()}
        publish_preparation(work, 'evidence/receipt.json', encoded(receipt), clock=clock)
        return clock
    except BaseException:
        # Raw original output remains private; no failure is promoted to closure.
        try: publish_preparation(work, 'evidence/failed-commands.json', encoded(phase.records))
        except BaseException: pass
        raise


def cleanup_receipt(work, value, clock):
    fields = {'schemaVersion', 'phase', 'status', 'source', 'workflow', 'ref', 'wrapperReturncodeRequired',
        'commands', 'sourcePrePost', 'toolRosterSha256', 'acquisitionSha256', 'acquisitionClock',
        'sdkObservationSha256', 'sdkMetadata', 'aab', 'fixtureSha256', 'verificationSha256',
        'workIdentity', 'disposalIdentities', 'protectedRegistration', 'uiQualification', 'phaseClock',
        'aInputStatement', 'aInputOriginals', 'lockOriginals', 'inventorySha256'}
    need(type(value) is dict and set(value) == fields and type(value['schemaVersion']) is int
         and value['schemaVersion'] == 1 and value['phase'] == 'B'
         and value['status'] == 'closed-awaiting-distinct-b-data-review'
         and value['source'] == os.environ['GITHUB_SHA'] and value['workflow'] == WORKFLOW and value['ref'] == REF
         and value['sourcePrePost'] is True and type(value['wrapperReturncodeRequired']) is int
         and value['wrapperReturncodeRequired'] == 0 and value['protectedRegistration'] is False
         and value['uiQualification'] is False and value['sdkMetadata'] == SDK_METADATA, 'cleanup-receipt')
    clock_record(value['phaseClock'], PHASE_SECONDS); clock_record(value['acquisitionClock'], ACQUISITION_SECONDS)
    _, task, jdk = b_arguments(work)
    head = ['/usr/bin/git', '-C', str(SOURCE), 'rev-parse', 'HEAD']
    clean = ['/usr/bin/git', '-C', str(SOURCE), 'status', '--porcelain=v1', '--untracked-files=all']
    expected = [('source-head-pre', head, 10, 4096), ('source-clean-pre', clean, 10, 16384),
        ('android-public-tool-acquisition', [sys.executable, '-I', '-S', '-B',
            str(SOURCE / 'desktop/tools/macos_android_dependency_preparation.py'), 'acquire'], 840, 16384),
        ('android-dependency-jdk-version', [str(jdk / 'bin/java'), '-version'], 15, 8192),
        ('android-dependency-gradle-version', ['/bin/sh', str(work / 'tools/gradle/bin/gradle'), '--version'], 15, 8192),
        ('android-dependency-locked-task', task, 900, 2 << 20),
        ('source-head-post', head, 10, 4096), ('source-clean-post', clean, 10, 16384)]
    need(type(value['commands']) is list and len(value['commands']) == len(expected), 'cleanup-command-count')
    for record, (role, argv, cap, limit) in zip(value['commands'], expected):
        need(type(record) is dict and set(record) == {'role', 'returncode', 'timeoutSeconds', 'roleCapSeconds',
             'outputLimitBytes', 'argvSha256', 'stdoutBytes', 'stdoutSha256', 'stderrBytes', 'stderrSha256'}, 'cleanup-command-fields')
        need(record['role'] == role and type(record['returncode']) is int and record['returncode'] == 0
             and type(record['roleCapSeconds']) is int and record['roleCapSeconds'] == cap
             and type(record['timeoutSeconds']) is int and 1 <= record['timeoutSeconds'] <= cap
             and type(record['outputLimitBytes']) is int and record['outputLimitBytes'] == limit
             and record['argvSha256'] == digest(N.encoded(argv)), 'cleanup-command-original')
        need(all(type(record[k]) is int and 0 <= record[k] <= limit for k in ('stdoutBytes', 'stderrBytes'))
             and record['stdoutBytes'] + record['stderrBytes'] <= limit
             and all(type(record[k]) is str and re.fullmatch('[0-9a-f]{64}', record[k])
                     for k in ('stdoutSha256', 'stderrSha256')), 'cleanup-command-output')
        if role.startswith('source-'):
            body = (os.environ['GITHUB_SHA'] + '\n').encode() if 'head' in role else b''
            need(record['stdoutBytes'] == len(body) and record['stdoutSha256'] == digest(body)
                 and record['stderrBytes'] == 0 and record['stderrSha256'] == digest(b''), 'cleanup-source-original')
    acquired, sha = acquisition_receipt(work, clock)
    need(value['acquisitionSha256'] == sha and value['sdkObservationSha256'] == acquired['sdkObservationSha256']
         and value['toolRosterSha256'] == acquired['toolRosterSha256'], 'cleanup-acquisition-binding')
    project, verification = resources()
    inputs = read_b_inputs(SOURCE, B_DATA, project, verification,
        RESOURCES['desktop/tools/android_dependency_preparation_data/verification-v1.xml'], clock)
    need(value['aInputStatement'] == b_input_statement(inputs['nomination'])
         and value['aInputOriginals'] == {name: list(identity) for name, identity in inputs['originals'].items()},
         'cleanup-b-input-binding')
    b_lock_post(work, value['lockOriginals'], clock)
    need(all(value['lockOriginals'][relative][1] == inputs['nomination']['resources'][resource][1]
             for resource, relative in (('buildscript-gradle.lockfile', 'buildscript-gradle.lockfile'),
                                        ('app-gradle.lockfile', 'app/gradle.lockfile'))),
         'cleanup-b-lock-input-binding')
    inventory_raw, _ = read(work / 'evidence/inventory.json', 1 << 20, clock=clock)
    need(inventory_raw == encoded(b_inventory_document(inputs))
         and value['inventorySha256'] == digest(inventory_raw), 'cleanup-b-inventory-binding')
    b_input_post(SOURCE, inputs, clock)
    need(value['fixtureSha256'] == digest(project) and value['verificationSha256'] == digest(verification), 'cleanup-resource-binding')
    for entry in SDK_METADATA:
        raw, _ = read(SOURCE / entry['path'], 32768, clock=clock)
        need((len(raw), digest(raw)) == (entry['bytes'], entry['sha256']), 'cleanup-sdk-source-binding')
    need(type(value['aab']) is dict and set(value['aab']) == {'bytes', 'sha256'}
         and type(value['aab']['bytes']) is int and 0 < value['aab']['bytes'] <= 64 << 20
         and type(value['aab']['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['aab']['sha256']), 'cleanup-aab-binding')
    need(type(value['disposalIdentities']) is dict and set(value['disposalIdentities']) == {'archives', 'tools', 'run'}, 'cleanup-disposal-fields')
    for identity in [value['workIdentity'], *value['disposalIdentities'].values()]:
        need(type(identity) is list and len(identity) == 5 and all(type(v) is int and v >= 0 for v in identity)
             and identity[3] == os.getuid() and stat.S_ISDIR(identity[2])
             and stat.S_IMODE(identity[2]) == 0o700, 'cleanup-directory-identity')


def restore_sdk_for_cleanup(work, private, value, clock):
    # No full tool rehash: extract SDK identity from these same authenticated raws.
    rows, _ = read(work / 'tool-roster.json', 4 << 20, clock=clock)
    dirs, _ = read(work / 'directory-roster.json', 4 << 20, clock=clock)
    need(digest(rows + dirs) == value['toolRosterSha256'], 'cleanup-sdk-roster-binding')
    directories = json.loads(dirs, object_pairs_hook=N.pairs,
                             parse_constant=lambda _: (_ for _ in ()).throw(Refused('cleanup-sdk-roster-shape')))
    need(type(directories) is dict and len(directories) <= ENTRIES, 'cleanup-sdk-roster-shape')
    expected = directories.get('sdk')
    need(type(expected) is list and len(expected) == 5
         and all(type(v) is int and v >= 0 for v in expected)
         and stat.S_ISDIR(expected[2]) and stat.S_IMODE(expected[2]) == 0o500
         and expected[3] == os.getuid(), 'cleanup-sdk-roster-row')
    fds, originals = private['fds'], private['originals']
    tools_fd = sdk_fd = None; primary = None
    try:
        clock.check(); recheck_chain(fds, originals)
        tools_fd = os.open('tools', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=fds[-1])
        tools_before = nine(os.fstat(tools_fd))[:5]
        need(list(tools_before) == value['disposalIdentities']['tools']
             and tools_before == nine(os.stat('tools', dir_fd=fds[-1], follow_symlinks=False))[:5],
             'cleanup-sdk-tools-original')
        sdk_fd = os.open('sdk', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=tools_fd)
        before = nine(os.fstat(sdk_fd))[:5]
        need(list(before) == expected
             and before == nine(os.stat('sdk', dir_fd=tools_fd, follow_symlinks=False))[:5],
             'cleanup-sdk-original')
        clock.check(); os.fchmod(sdk_fd, 0o700); os.fsync(sdk_fd)
        after = nine(os.fstat(sdk_fd))[:5]
        need(after[:2] + after[3:] == before[:2] + before[3:]
             and stat.S_ISDIR(after[2]) and stat.S_IMODE(after[2]) == 0o700
             and after == nine(os.stat('sdk', dir_fd=tools_fd, follow_symlinks=False))[:5],
             'cleanup-sdk-post')
        need(nine(os.fstat(tools_fd))[:5] == tools_before
             == nine(os.stat('tools', dir_fd=fds[-1], follow_symlinks=False))[:5], 'cleanup-sdk-tools-post')
        recheck_chain(fds, originals); clock.check()
    except BaseException as error:
        primary = error; raise
    finally:
        failure = None
        # Consume every adopted descriptor once; even a consuming close may fail.
        closing = [tools_fd, sdk_fd]; tools_fd = sdk_fd = None
        for fd in reversed(closing):
            if fd is not None:
                try: os.close(fd)
                except BaseException:
                    if failure is None: failure = Refused('original-close-unknown')
        if primary is None and failure is not None: raise failure


def cleanup(work, *, private=None):
    admit_b_nomination(B_DATA)
    need(os.environ.get('MRK_PREPARATION_WRAPPER_RETURN') == '0'
         and os.environ.get('MRK_PREPARATION_EVIDENCE_UPLOAD') == 'success'
         and private is not None, 'cleanup-original-gates')
    clock = N.PhaseClock(90)  # Within unchanged two-minute disposal step.
    raw, _ = read(work / 'evidence/receipt.json', 16384, clock=clock)
    value = N.document(raw); cleanup_receipt(work, value, clock)
    fds, originals = private['fds'], private['originals']
    recheck_chain(fds, originals); fd = fds[-1]
    need(list(nine(os.fstat(fd))[:5]) == value['workIdentity'] and shutil.rmtree.avoids_symlink_attacks, 'cleanup-owned-parent')
    for leaf in ('archives', 'tools', 'run'):
        need(list(nine(os.stat(leaf, dir_fd=fd, follow_symlinks=False))[:5]) == value['disposalIdentities'][leaf], 'cleanup-child-identity')
    restore_sdk_for_cleanup(work, private, value, clock)
    recheck_chain(fds, originals)
    for leaf in ('archives', 'tools', 'run'):
        need(list(nine(os.stat(leaf, dir_fd=fd, follow_symlinks=False))[:5]) == value['disposalIdentities'][leaf], 'cleanup-child-identity')
    for leaf in ('archives', 'tools', 'run'):
        clock.check(); recheck_chain(fds, originals)
        shutil.rmtree(leaf, dir_fd=fd)
    os.fsync(fd); recheck_chain(fds, originals)
    return clock


def main():
    global N, P, C
    private = None
    stage = 'work-admission'
    result = 78
    final_clock = None
    try:
        # A safe original work directory is required even for early diagnostics.
        candidate = os.environ.get('MRK_ANDROID_PREPARATION_WORK', '')
        need(re.fullmatch('/Users/runner/work/_temp/mrk-android-dependencies[.][A-Za-z0-9]{8}', candidate), 'private-work-name')
        private = admit_work(Path(candidate))
        stage = 'scope-context'
        need(len(sys.argv) == 2 and ((RUN_SCOPE == 'observe-sdk' and sys.argv[1] == 'observe-sdk')
             or (RUN_SCOPE == 'prepare-b' and sys.argv[1] in ('prepare-b', 'acquire', 'cleanup'))), 'fixed-source-scope')
        work = context()
        need(work == private['path'], 'private-work-context')
        recheck_chain(private['fds'], private['originals'])
        stage = 'normal-helper-load'
        N = load('_mrk_android_preparation_normal', 'desktop/tools/macos_normal_ui_runner.py')
        stage = 'transport-helper-load'
        P = load('_mrk_android_preparation_transport', 'desktop/tools/macos_android_supplier_preparation.py')
        if sys.argv[1] == 'acquire':
            stage = 'archive-helper-load'
            C = load('_mrk_android_preparation_correspondence', 'desktop/tools/macos_android_supplier_correspondence.py')
        stage = 'sdk-observation' if sys.argv[1] == 'observe-sdk' else sys.argv[1]
        if sys.argv[1] == 'observe-sdk':
            report = observe_sdk_current_use(work, private=private)
            need(report['status'] == 'observed-not-admitted' and 'reason' not in report
                 and report.get('originalsClosed') is True, 'sdk-observation-refused')
        else:
            final_clock = {'prepare-b': prepare, 'acquire': acquire, 'cleanup': cleanup}[sys.argv[1]](work, private=private)
        recheck_chain(private['fds'], private['originals'])
        result = 0
    except BaseException as error:
        code = str(error) if isinstance(error, Refused) else 'preparation-original-failure'
        if not re.fullmatch('[a-z0-9-]{1,96}', code): code = 'preparation-original-failure'
        if private is not None:
            try:
                name = 'observe-sdk-failure.json' if RUN_SCOPE == 'observe-sdk' else (sys.argv[1] if len(sys.argv) == 2 and sys.argv[1] in ('acquire', 'cleanup') else 'prepare-b') + '-failure.json'
                report = {'status': 'refused', 'stage': stage, 'reason': code,
                    'scope': RUN_SCOPE, 'nativeOrTaskSuccess': False, 'cleanupAuthorized': False}
                try:
                    detail = getattr(error, 'tool_namespace', None)
                    if (isinstance(error, Refused) and code == 'tool-namespace-changed'
                            and type(detail) is dict and set(detail) == {
                                'change', 'toolFamily', 'relativeBytes', 'relativeSha256', 'publicPath'}
                            and type(detail['change']) is str and detail['change'] in ('unexpected', 'duplicate')
                            and type(detail['toolFamily']) is str and detail['toolFamily'] in ('jdk', 'sdk', 'gradle', 'other')
                            and type(detail['relativeBytes']) is int and 0 < detail['relativeBytes'] <= 4096
                            and type(detail['relativeSha256']) is str
                            and re.fullmatch('[0-9a-f]{64}', detail['relativeSha256'])
                            and (detail['publicPath'] is None or (
                                type(detail['publicPath']) is str and detail['publicPath'] == 'sdk/.knownPackages'
                                and detail['toolFamily'] == 'sdk'
                                and detail['relativeBytes'] == len(b'sdk/.knownPackages')
                                and detail['relativeSha256'] == digest(b'sdk/.knownPackages')))):
                        report['toolNamespace'] = detail
                except BaseException:
                    pass  # Malformed optional detail cannot suppress the base failure.
                publish_json(private, name, report)
            except BaseException:
                pass  # An unsafe/unknown original cannot be reopened for diagnostics.
        result = 78
    finally:
        if private is not None:
            try: close_chain(private['fds'], private['originals'])
            except BaseException: result = 78
    if result == 0 and final_clock is not None:
        try: final_clock.finish()
        except BaseException: result = 78
    return result

if __name__ == '__main__':
    raise SystemExit(main())
