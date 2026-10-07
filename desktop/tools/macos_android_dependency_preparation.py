#!/usr/bin/env python3
"""Fixed ARM engineering AGP lock preparation A; never protected UI admission.

No phase B exists before distinct review of genuine A locks and inventory.
SDK_CURRENT_USE is deliberately unavailable until an actual provisioned Mac
current-use cohort is independently admitted. A receipt marker is not a licence.
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
RUN_SCOPE = 'observe-sdk'  # Fixed SOURCE selection; no workflow/runtime switch.
SDK_CURRENT_USE = None  # Not an agreement, approval flag, guessed path or receipt.
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
RESOURCES = {'desktop/tools/android_dependency_preparation_data/project-v1.json': [6125, 'cbcc8c69f468ae157611614f8dc30f5037f8ef39f1c095d0d7aba31c24f58c37'], 'desktop/tools/android_dependency_preparation_data/verification-v1.xml': [90045, '5d00856c785363da964e00da72ad38571cfd088da915ebe86cf20640bb1c7545']}
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


def close_chain(fds, originals):
    """Consume all originals once and preserve this call's first own failure."""
    failure = None
    try: recheck_chain(fds, originals)
    except BaseException as error: failure = error
    closing = fds[:]
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
    limits = {'sdk-observation.json': 16384, 'observe-sdk-failure.json': 4096}
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


def file_digest(path, limit, clock):
    fds = chain(path.parent); fd = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fds[-1])
        before = nine(os.fstat(fd))
        need(stat.S_ISREG(before[2]) and before[3] == os.getuid() and before[5] == 1
             and not before[2] & 0o022 and 0 <= before[6] <= limit, 'artifact-original')
        sha = hashlib.sha256(); prefix = b''
        for at in range(0, before[6], CHUNK):
            clock.check(); amount = min(CHUNK, before[6] - at); part = os.pread(fd, amount, at)
            need(len(part) == amount, 'artifact-short'); sha.update(part)
            if at == 0: prefix = part[:4]
        need(not os.pread(fd, 1, before[6]) and nine(os.fstat(fd)) == before
             == nine(os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)), 'artifact-post')
        return before[6], sha.hexdigest(), prefix
    finally:
        if fd is not None: os.close(fd)
        for parent in reversed(fds): os.close(parent)


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

def observe_sdk_current_use(work, *, private=None):
    """Five fixed readonly SDK originals; absence is DATA, never legal acceptance."""
    owned_private = private is None
    if owned_private: private = admit_work(work)
    clock = N.PhaseClock(30)
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
    try:
        publish_json(private, 'sdk-observation.json', report)
        need(report['status'] == 'observed-not-admitted' and 'reason' not in report, 'sdk-observation-refused')
        clock.finish()
        return report
    finally:
        if owned_private: close_chain(private['fds'], private['originals'])


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
        fds = chain(self.work / 'tools')
        prefix = []
        try:
            for part in parts[:-1]:
                self.point(); prefix.append(part)
                try:
                    need(self.entries < ENTRIES, 'directory-entry-bound')
                    os.mkdir(part, 0o700, dir_fd=fds[-1]); self.entries += 1
                except FileExistsError: pass
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fds[-1])
                fds.append(fd); state = nine(os.fstat(fd))
                need(state[3] == os.getuid() and stat.S_IMODE(state[2]) == 0o700, 'private-tool-directory')
                relative_dir = '/'.join(prefix)
                before = self.directories.setdefault(relative_dir, list(state[:5]))
                need(before == list(state[:5]), 'tool-directory-changed')
            return fds, parts[-1]
        except BaseException:
            for fd in reversed(fds): os.close(fd)
            raise

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
        fds, leaf = self.parent(target)
        fd = None
        try:
            fd = os.open(leaf, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=fds[-1])
            s = os.fstat(fd)
            need(s.st_uid == os.getuid() and s.st_nlink == 1 and s.st_size == 0
                 and stat.S_IMODE(s.st_mode) == 0o600, 'new-tool-original')
            self.active = (fd, fds, leaf, target, row[3], 0, hashlib.sha256(), mode)
            fd = None
        finally:
            if fd is not None: os.close(fd)
            if self.active is None:
                for parent in reversed(fds): os.close(parent)

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
        fd, parents, leaf, target, size, at, sha, mode = self.active
        self.active = None
        try:
            need(at == size and sha.hexdigest() == row[4], 'tool-payload-digest')
            os.fsync(fd)
            before = nine(os.fstat(fd))
            observed = hashlib.sha256()
            for pos in range(0, size, CHUNK):
                amount = min(CHUNK, size - pos); self.charge_read(amount)
                data = os.pread(fd, amount, pos)
                need(len(data) == amount, 'tool-readback-short'); observed.update(data)
            need(not os.pread(fd, 1, size) and observed.hexdigest() == row[4]
                 and nine(os.fstat(fd)) == before
                 == nine(os.stat(leaf, dir_fd=parents[-1], follow_symlinks=False)), 'tool-readback-post')
            self.roster.append({'path': target, 'bytes': size, 'sha256': row[4],
                                'vendorMode': row[2], 'mode': mode & ~0o222, 'identity': list(before)})
            self.files += 1
        finally:
            os.close(fd)
            for parent in reversed(parents): os.close(parent)

    def terminal_row(self, row):
        self.point(); self.entries += 1
        need(self.entries <= ENTRIES, 'aggregate-archive-entry-bound')
        target = self.target(row[0])
        if target is None: return
        if row[1] == 'directory':
            # Observed JDK GNU directory sgid is DATA, never installed authority.
            need(row[2] in (0o40755, 0o42755), 'unsupported-vendor-directory-mode')
            parents, _ = self.parent(target + '/__directory_only__')
            for fd in reversed(parents): os.close(fd)
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
                response.close(); response = None
                response = request(address); headers = P.response_headers(response)
            need(response.code == 200 and 'location' not in headers
                 and headers.get('content-encoding', 'identity') == 'identity'
                 and ('content-length' not in headers or int(headers['content-length']) == role['bytes']), 'archive-response')
            fd = os.open(target, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
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
            response.close(); response = None
            os.fsync(fd)
            self.archive_fd, self.archive_before, self.archive_path = fd, nine(os.fstat(fd)), target
            need(self.archive_before[5] == 1 and self.archive_before[6] == role['bytes']
                 and stat.S_IMODE(self.archive_before[2]) == 0o600, 'archive-original')
            capture = C.compile_archive(self, C.Pin(role['role'], role['bytes'], role['sha256']), observer=self)
            capture.consume_rows(self.terminal_row)
            self.verify_binding()
        finally:
            if self.active is not None:
                active, self.active = self.active, None
                os.close(active[0])
                for parent in reversed(active[1]): os.close(parent)
            if response is not None: response.close()
            if fd is not None: os.close(fd)
            self.archive_fd = None

    def seal(self):
        need(self.files > 0 and len({r['path'] for r in self.roster}) == self.files, 'tool-roster')
        for row in self.roster:
            self.point()
            fds, leaf = self.parent(row['path']); fd = None
            try:
                fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fds[-1])
                need(list(nine(os.fstat(fd))) == row['identity'], 'tool-preseal-original')
                os.fchmod(fd, row['mode']); os.fsync(fd)
                after = nine(os.fstat(fd))
                need(nine(os.stat(leaf, dir_fd=fds[-1], follow_symlinks=False)) == after
                     and stat.S_IMODE(after[2]) == row['mode'], 'tool-seal-post')
                row['identity'] = list(after)
            finally:
                if fd is not None: os.close(fd)
                for parent in reversed(fds): os.close(parent)
        aapt = next(r for r in self.roster if r['path'] == 'gradle/native/aapt2/aapt2')
        need((aapt['bytes'], aapt['sha256'], aapt['vendorMode']) == (11143368,
             '213e3d049e2c85daa930ed777bbd5627c1c5479a8d6698029b8f9c0161ad0a7e', 0o100755), 'osx-aapt2-member')
        raw = encoded(self.roster); need(len(raw) <= 4 << 20, 'tool-roster-bound')
        N.exclusive_output(self.work / 'tool-roster.json', raw, 4 << 20)
        N.exclusive_output(self.work / 'directory-roster.json', encoded(self.directories), 4 << 20)
        self.clock.finish()

def acquire(work):
    # This child is reachable only through the fixed owned acquisition role.
    need(os.environ.get('MRK_ANDROID_ACQUISITION_CHILD') == '1', 'acquisition-original-required')
    a = Acquisition(work)
    ca, ca_identity = read(Path('/private/etc/ssl/cert.pem'), 1 << 20, clock=a.clock)
    need(ca_identity[3] == 0, 'root-owned-stock-ca')
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.verify_mode = ssl.CERT_REQUIRED; tls.check_hostname = True
    tls.load_verify_locations(cadata=ca.decode('ascii'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), P.NoRedirect(), urllib.request.HTTPSHandler(context=tls))
    for row in ARCHIVES: a.capture(row, opener)
    a.seal()
    N.exclusive_output(work / 'acquisition.json', encoded({'status': 'closed', 'archives': ARCHIVES,
        'archiveBytes': 469391018, 'toolBytes': a.writes, 'readBytes': a.reads,
        'files': a.files, 'entries': a.entries, 'stockCaSha256': digest(ca),
        'nativeExecuted': False, 'protectedRegistration': False}), 16384)


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
            need(relative in expected and relative not in found, 'tool-namespace-changed')
            found.add(relative); need(len(found) <= ENTRIES + FILES, 'tool-namespace-bound')
            if relative in directories:
                need(list(nine(os.lstat(path))[:5]) == directories[relative], 'tool-directory-post')
    need(found == expected, 'tool-namespace-incomplete')
    total = 0
    for row in rows:
        clock.check(); total += row['bytes']; need(total <= TOOL_BYTES, 'tool-total')
        path = work / 'tools' / row['path']; fds = chain(path.parent); fd = None
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fds[-1])
            before = nine(os.fstat(fd)); need(list(before) == row['identity'], 'tool-identity')
            sha = hashlib.sha256()
            for at in range(0, row['bytes'], CHUNK):
                clock.check(); count = min(CHUNK, row['bytes'] - at); part = os.pread(fd, count, at)
                need(len(part) == count, 'tool-short'); sha.update(part)
            need(not os.pread(fd, 1, row['bytes']) and sha.hexdigest() == row['sha256']
                 and nine(os.fstat(fd)) == before
                 == nine(os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)), 'tool-post')
        finally:
            if fd is not None: os.close(fd)
            for parent in reversed(fds): os.close(parent)
    return digest(raw + directories_raw)


def resources():
    bodies = {}
    for name, pin in RESOURCES.items():
        raw, _ = read(SOURCE / name, 128 << 10)
        need((len(raw), digest(raw)) == tuple(pin), 'fixture-resource-pin'); bodies[name] = raw
    return list(bodies.values())


def materialize(work, project_raw, verification):
    value = json.loads(project_raw)
    need(set(value) == {'schemaVersion', 'files', 'stages'} and value['schemaVersion'] == 1
         and value['stages'] == {} and len(value['files']) == 9, 'fixture-resource-shape')
    originals = {}
    for relative, content in value['files'].items():
        need(relative.startswith('project/'), 'fixture-project-prefix')
        name = relative.removeprefix('project/'); P.relative(name)
        body = base64.b64decode(content, validate=True)
        path = work / 'run/project' / name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        N.exclusive_output(path, body, 16384); originals[name] = digest(body)
    need(sum(len(base64.b64decode(r)) for r in value['files'].values()) == 4236, 'fixture-decoded-bound')
    N.exclusive_output(work / 'run/project/gradle/verification-metadata.xml', verification, 128 << 10)
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
            'locksAreOriginalGradleTaskOutputs': True, 'rows': sorted(rows, key=lambda r: tuple(r.values()))}


def source_original(phase, suffix):
    value = phase.call('source-head-' + suffix, ['/usr/bin/git', '-C', str(SOURCE), 'rev-parse', 'HEAD'], 10, 4096)
    need(value.returncode == 0 and value.stdout == (os.environ['GITHUB_SHA'] + '\n').encode(), 'source-head')
    value = phase.call('source-clean-' + suffix, ['/usr/bin/git', '-C', str(SOURCE), 'status', '--porcelain=v1', '--untracked-files=all'], 10, 16384)
    need(value.returncode == 0 and value.stdout == b'', 'source-clean')


def prepare(work):
    need(os.statvfs(work).f_bavail * os.statvfs(work).f_frsize >= 8 << 30, 'eight-gib-free-prerequisite')
    observed_sdk = observe_sdk_current_use(work)
    admit_sdk_current_use(observed_sdk)  # Refuses BEFORE download/materialization/native task.
    owner = N.load_normal_owner(SOURCE)
    project_raw, verification = resources()
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
    source_original(acquisition, 'pre')
    result = acquisition.call('android-public-tool-acquisition', [sys.executable, '-I', '-S', '-B',
        str(SOURCE / 'desktop/tools/macos_android_dependency_preparation.py'), 'acquire'], 840, 16384)
    N.exclusive_output(work / 'evidence/acquisition-commands.json', encoded(acquisition.records), 16384)
    need(result.returncode == 0, 'acquisition-original-return')
    acquired_raw, _ = read(work / 'acquisition.json', 16384, clock=clock)
    need(json.loads(acquired_raw)['status'] == 'closed', 'acquisition-finality')
    clock.finish()
    clock = N.PhaseClock(PHASE_SECONDS)
    originals = materialize(work, project_raw, verification)
    before_tools = tool_post(work, clock)
    env, command, jdk = arguments(work)
    phase = N.NormalPhase(owner, env, work / 'run/project', clock)
    try:
        for role, argv in [('android-dependency-jdk-version', [str(jdk / 'bin/java'), '-version']),
                           ('android-dependency-gradle-version', ['/bin/sh', str(work / 'tools/gradle/bin/gradle'), '--version'])]:
            result = phase.call(role, argv, 15, 8192); need(result.returncode == 0, 'tool-version-original-return')
        result = phase.call('android-dependency-lock-task', command, 900, 2 << 20)
        need(result.returncode == 0, 'gradle-original-return')
        locks = {}
        for name in ('buildscript-gradle.lockfile', 'app/gradle.lockfile'):
            raw, _ = read(work / 'run/project' / name, 32 << 10, clock=clock)
            need(raw and raw.startswith(b'# This is a Gradle generated file'), 'genuine-lock-shape')
            locks[name] = raw
        need(sum(map(len, locks.values())) <= 32 << 10, 'locks-combined-bound')
        actual = inventory(work, verification, clock)
        aab_size, aab_sha, prefix = file_digest(work / 'run/project/app/build/outputs/bundle/release/app-release.aab', 64 << 20, clock)
        need(prefix == b'PK\x03\x04', 'actual-aab-required')
        for name, sha in originals.items():
            raw, _ = read(work / 'run/project' / name, 128 << 10, clock=clock)
            need(digest(raw) == sha, 'project-source-post')
        source_original(phase, 'post')
        need(tool_post(work, clock) == before_tools and resources() == [project_raw, verification], 'source-tools-post')
        N.exclusive_output(work / 'evidence/inventory.json', encoded(actual), 1 << 20)
        for name, raw in locks.items():
            N.exclusive_output(work / 'evidence' / name.replace('/', '-'), raw, 32 << 10)
        receipt = {'schemaVersion': 1, 'phase': 'A', 'status': 'closed-awaiting-distinct-data-review',
            'source': os.environ['GITHUB_SHA'], 'workflow': WORKFLOW, 'ref': REF,
            'wrapperReturncodeRequired': 0, 'commands': acquisition.records + phase.records,
            'sourcePrePost': True, 'toolRosterSha256': before_tools,
            'aab': {'bytes': aab_size, 'sha256': aab_sha}, 'fixtureSha256': digest(project_raw),
            'verificationSha256': digest(verification), 'workIdentity': root_identity,
            'disposalIdentities': identities, 'protectedRegistration': False, 'uiQualification': False,
            'phaseClock': clock.before_publication()}
        N.exclusive_output(work / 'evidence/receipt.json', encoded(receipt), 16384)
        clock.finish()
    except BaseException:
        # Raw original output remains private; no failure is promoted to closure.
        N.exclusive_output(work / 'evidence/failed-commands.json', encoded(phase.records), 16384)
        raise


def cleanup(work):
    need(os.environ.get('MRK_PREPARATION_WRAPPER_RETURN') == '0'
         and os.environ.get('MRK_PREPARATION_EVIDENCE_UPLOAD') == 'success', 'cleanup-original-gates')
    raw, _ = read(work / 'evidence/receipt.json', 16384)
    value = json.loads(raw)
    need(value['status'] == 'closed-awaiting-distinct-data-review' and value['source'] == os.environ['GITHUB_SHA']
         and value['sourcePrePost'] is True and value['ref'] == REF
         and [r['role'] for r in value['commands']] == ['source-head-pre', 'source-clean-pre', 'android-public-tool-acquisition',
             'android-dependency-jdk-version', 'android-dependency-gradle-version', 'android-dependency-lock-task', 'source-head-post', 'source-clean-post']
         and all(type(r['returncode']) is int and r['returncode'] == 0 for r in value['commands']), 'cleanup-receipt')
    parents = chain(work)
    try:
        fd = parents[-1]
        need(list(nine(os.fstat(fd))[:5]) == value['workIdentity'] and shutil.rmtree.avoids_symlink_attacks, 'cleanup-owned-parent')
        # Preflight all literal children BEFORE the first disposal, then use this retained FD.
        for leaf in ('archives', 'tools', 'run'):
            need(list(nine(os.stat(leaf, dir_fd=fd, follow_symlinks=False))[:5]) == value['disposalIdentities'][leaf], 'cleanup-child-identity')
        for leaf in ('archives', 'tools', 'run'):
            shutil.rmtree(leaf, dir_fd=fd)
        os.fsync(fd)
    finally:
        for fd in reversed(parents): os.close(fd)


def main():
    global N, P, C
    private = None
    stage = 'work-admission'
    result = 78
    try:
        # A safe original work directory is required even for early diagnostics.
        candidate = os.environ.get('MRK_ANDROID_PREPARATION_WORK', '')
        need(re.fullmatch('/Users/runner/work/_temp/mrk-android-dependencies[.][A-Za-z0-9]{8}', candidate), 'private-work-name')
        private = admit_work(Path(candidate))
        stage = 'scope-context'
        need(len(sys.argv) == 2 and ((RUN_SCOPE == 'observe-sdk' and sys.argv[1] == 'observe-sdk')
             or (RUN_SCOPE == 'prepare-a' and sys.argv[1] in ('prepare-a', 'acquire', 'cleanup'))), 'fixed-source-scope')
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
        stage = 'sdk-observation' if sys.argv[1] == 'observe-sdk' else 'dormant-preparation'
        if sys.argv[1] == 'observe-sdk':
            report = observe_sdk_current_use(work, private=private)
            need(report['status'] == 'observed-not-admitted' and 'reason' not in report
                 and report.get('originalsClosed') is True, 'sdk-observation-refused')
        else:
            {'prepare-a': prepare, 'acquire': acquire, 'cleanup': cleanup}[sys.argv[1]](work)
        recheck_chain(private['fds'], private['originals'])
        result = 0
    except BaseException as error:
        code = str(error) if isinstance(error, Refused) else 'observation-original-failure'
        if not re.fullmatch('[a-z0-9-]{1,96}', code): code = 'observation-original-failure'
        if private is not None:
            try:
                publish_json(private, 'observe-sdk-failure.json', {'status': 'refused', 'stage': stage,
                    'reason': code, 'scope': RUN_SCOPE, 'nativeOrTaskSuccess': False, 'cleanupAuthorized': False})
            except BaseException:
                pass  # An unsafe/unknown original cannot be reopened for diagnostics.
        result = 78
    finally:
        if private is not None:
            try: close_chain(private['fds'], private['originals'])
            except BaseException: result = 78
    return result

if __name__ == '__main__':
    raise SystemExit(main())
