#!/usr/bin/env python3
"""Two tiny owned-directory transitions; no producer/signing qualification."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import resource
import stat
import sys
import time

ROOT = Path('/Users/runner/work/mobile-release-kit/mobile-release-kit')
PARENT = Path('/Users/runner/work/_temp')
REF = 'refs/heads/verify/desktop-macos-directory-identity'
WORKFLOW = 'Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-directory-identity.yml@' + REF
PUBLIC = 'directory-identity-public.json'
READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
NAMES = ('first.bin', 'second.bin')
FIELDS = ('dev', 'ino', 'type', 'mode', 'uid', 'gid', 'flags', 'links', 'size', 'mtime_ns', 'ctime_ns')


class Refused(Exception):
    pass


def need(value):
    if not value:
        raise Refused()


def tick(end):
    need(time.monotonic() < end)


def full(s):
    return (s.st_dev, s.st_ino, stat.S_IFMT(s.st_mode), s.st_mode,
            s.st_uid, s.st_gid, s.st_flags, s.st_nlink, s.st_size,
            s.st_mtime_ns, s.st_ctime_ns)


def stable(value):
    return value[:7]


def close(row):
    fd, row['fd'] = row['fd'], None  # Consume even when close refuses; never retry.
    if fd is not None:
        os.close(fd)
    row['closed'] = True


def parent_post(rows):
    for row in rows:
        held = full(os.fstat(row['fd']))
        named = full(os.stat(row['name'], dir_fd=row['parent'], follow_symlinks=False))
        need(held == named and stable(held) == row['stable'])


def root_snapshot(parent, root):
    held = full(os.fstat(root['fd']))
    named = full(os.stat(root['name'], dir_fd=parent['fd'], follow_symlinks=False))
    need(held == named and stable(held) == root['stable'])
    need(0 <= held[7] <= 65535)
    return held


def files_post(root, files):
    need(set(os.listdir(root['fd'])) == {row['name'] for row in files})
    for row in files:
        held = full(os.fstat(row['fd']))
        named = full(os.stat(row['name'], dir_fd=root['fd'], follow_symlinks=False))
        need(held == named == row['original'])


def context(environment):
    source = environment.get('GITHUB_SHA', '')
    target = environment.get('MRK_DIRECTORY_TARGET', '')
    hosts = {'aarch64-apple-darwin': ('arm64', 'ARM64'), 'x86_64-apple-darwin': ('x86_64', 'X64')}
    need(target in hosts)
    fd = os.open('/System/Library/CoreServices/SystemVersion.plist', READ)
    try:
        version_data = os.pread(fd, 8193, 0); need(len(version_data) <= 8192)
    finally:
        os.close(fd)
    product = plistlib.loads(version_data).get('ProductVersion', '')
    need(isinstance(product, str) and re.fullmatch(r'26(?:\.[0-9]{1,2}){1,2}', product) is not None)
    host = os.uname()
    expected = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': REF,
                'GITHUB_JOB': 'directory-identity', 'MRK_PUSH_EVENT_AFTER': source,
                'GITHUB_REPOSITORY': 'Apdelrahman1911/mobile-release-kit', 'GITHUB_WORKSPACE': str(ROOT),
                'GITHUB_WORKFLOW_REF': WORKFLOW, 'GITHUB_WORKFLOW_SHA': source, 'RUNNER_TEMP': str(PARENT),
                'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'macOS', 'RUNNER_ARCH': hosts[target][1]}
    need(re.fullmatch('[0-9a-f]{40}', source) is not None and source != '0' * 40
         and all(environment.get(k) == value for k, value in expected.items())
         and host.sysname == 'Darwin' and host.machine == hosts[target][0]
         and os.getuid() > 0 and os.getuid() == os.geteuid() and os.getgid() == os.getegid()
         and Path(__file__).absolute() == ROOT / 'desktop/tools/macos_directory_identity_probe.py'
         and (ROOT / '.git/HEAD').read_bytes() == source.encode() + b'\n')
    ids = [environment.get(k, '') for k in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')]
    need(all(re.fullmatch('[1-9][0-9]{0,19}', value) is not None for value in ids))
    digest = environment.get('MRK_DIRECTORY_SOURCE_SHA256', '')
    need(re.fullmatch('[0-9a-f]{64}', digest) is not None)
    return dict(source=source, workflowSource=source, runId=ids[0], runAttempt=ids[1], target=target,
                hostMajor=26, observerSourceSha256=digest)


def observe(end):
    parents, files, root = [], [], None
    retired = False
    result = None
    failed = False
    try:
        path = Path('/')
        for name in ('/', 'Users', 'runner', 'work', '_temp'):
            tick(end)
            parent = parents[-1]['fd'] if parents else None
            fd = os.open(name, READ | os.O_DIRECTORY, dir_fd=parent)
            row = dict(fd=fd, name=name, parent=parent, closed=False)
            parents.append(row)  # Register the original before any fallible observation.
            held = full(os.fstat(fd))
            named = full(os.stat(name, dir_fd=parent, follow_symlinks=False))
            need(held == named and held[2] == stat.S_IFDIR
                 and held[4] in (0, os.getuid()) and not held[3] & 0o7022)
            row['stable'] = stable(held)
            if name != '/':
                path /= name
        need(path == PARENT)
        parent_post(parents)
        name = 'mrk-directory-identity-' + os.urandom(16).hex()
        os.mkdir(name, 0o700, dir_fd=parents[-1]['fd'])
        root = dict(fd=None, name=name, closed=False, created=True)
        root['fd'] = os.open(name, READ | os.O_DIRECTORY, dir_fd=parents[-1]['fd'])
        held = full(os.fstat(root['fd']))
        need(held == full(os.stat(name, dir_fd=parents[-1]['fd'], follow_symlinks=False))
             and held[3] == stat.S_IFDIR | 0o700 and held[4:6] == (os.getuid(), os.getgid()) and held[6] == 0)
        root['stable'] = stable(held)
        before = root_snapshot(parents[-1], root)
        need(not os.listdir(root['fd']))
        transitions = []
        for name in NAMES:
            tick(end); parent_post(parents); files_post(root, files)
            need(root_snapshot(parents[-1], root) == before)
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=root['fd'])
            row = dict(fd=fd, name=name, closed=False)
            files.append(row)
            held = full(os.fstat(fd))
            need(held == full(os.stat(name, dir_fd=root['fd'], follow_symlinks=False))
                 and held[3] == stat.S_IFREG | 0o600 and held[4:6] == (os.getuid(), os.getgid())
                 and held[6:9] == (0, 1, 0))
            row['original'] = held
            after = root_snapshot(parents[-1], root)
            files_post(root, files); parent_post(parents); tick(end)
            transitions.append(dict(ordinal=len(files), fieldsEqual=dict(zip(FIELDS, (a == b for a, b in zip(before, after)))),
                                    linksBefore=before[7], linksAfter=after[7], linksDelta=after[7] - before[7]))
            before = after
        result = transitions
    except BaseException:
        failed = True
    finally:
        # Delete only proven task-owned originals. A failed custody check keeps
        # the uncertain leaf; close attempts still consume our own handles once.
        try:
            need(root is not None and root['fd'] is not None and 'stable' in root)
            parent_post(parents); root_snapshot(parents[-1], root); files_post(root, files)
            for row in reversed(files):
                original = row['original']
                need(full(os.stat(row['name'], dir_fd=root['fd'], follow_symlinks=False)) == original)
                close(row)
                need(full(os.stat(row['name'], dir_fd=root['fd'], follow_symlinks=False)) == original)
                os.unlink(row['name'], dir_fd=root['fd'])
                row['retired'] = True
                root_snapshot(parents[-1], root)
                need(set(os.listdir(root['fd'])) == {v['name'] for v in files if not v.get('retired')})
            need(not os.listdir(root['fd']))
            original = root_snapshot(parents[-1], root)
            close(root)
            need(full(os.stat(root['name'], dir_fd=parents[-1]['fd'], follow_symlinks=False)) == original)
            os.rmdir(root['name'], dir_fd=parents[-1]['fd'])
            try:
                os.stat(root['name'], dir_fd=parents[-1]['fd'], follow_symlinks=False)
            except FileNotFoundError:
                retired = True
            need(retired)
            parent_post(parents)
        except BaseException:
            failed = True
        for row in [*reversed(files), *([root] if root is not None else []), *reversed(parents)]:
            if row['fd'] is not None:
                try:
                    close(row)
                except BaseException:
                    failed = True
        need(not failed and retired and result is not None
             and all(row['closed'] for row in parents + files + [root]))
    tick(end)
    return dict(transitions=result, originalClosesKnown=True, exactTaskRetired=True,
                diagnosisOnly=True, producerFixQualified=False, productReady=False)


def bound_observe(end, expected):
    row = dict(fd=None, closed=False)
    name = ROOT / 'desktop/tools/macos_directory_identity_probe.py'
    try:
        row['fd'] = os.open(name, READ)
        original = full(os.fstat(row['fd']))
        body = os.pread(row['fd'], 32769, 0)
        need(original == full(os.stat(name, follow_symlinks=False))
             and original[3] == stat.S_IFREG | 0o644 and original[4:6] == (os.getuid(), os.getgid())
             and original[6:9] == (0, 1, len(body)) and len(body) <= 32768
             and hashlib.sha256(body).hexdigest() == expected)
        result = observe(end)
        need(full(os.fstat(row['fd'])) == full(os.stat(name, follow_symlinks=False)) == original
             and os.pread(row['fd'], 32769, 0) == body)
        close(row)
        need(full(os.stat(name, follow_symlinks=False)) == original); tick(end)
        return result
    except BaseException:
        if row['fd'] is not None:
            try:
                close(row)
            except BaseException:
                pass
        raise Refused() from None


def publish(report, end):
    body = (json.dumps(report, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    need(len(body) <= 8192)
    parent = os.open(ROOT, READ | os.O_DIRECTORY)
    fd = None
    try:
        before = full(os.fstat(parent))
        need(before == full(os.stat(ROOT, follow_symlinks=False)) and before[2] == stat.S_IFDIR)
        fd = os.open(PUBLIC, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        offset = 0
        while offset < len(body):
            tick(end)
            count = os.write(fd, body[offset:]); need(count > 0); offset += count
        os.fsync(fd)
        original = full(os.fstat(fd))
        need(original == full(os.stat(PUBLIC, dir_fd=parent, follow_symlinks=False))
             and original[3] == stat.S_IFREG | 0o600 and original[4:6] == (os.getuid(), os.getgid())
             and original[6:9] == (0, 1, len(body)) and os.pread(fd, 8193, 0) == body)
        consumed, fd = fd, None
        os.close(consumed)
        need(original == full(os.stat(PUBLIC, dir_fd=parent, follow_symlinks=False)))
        after = full(os.fstat(parent))
        need(after == full(os.stat(ROOT, follow_symlinks=False)) and stable(after) == stable(before))
        tick(end)
    finally:
        try:
            if fd is not None:
                consumed, fd = fd, None
                os.close(consumed)
        finally:
            os.close(parent)


def main():
    end = time.monotonic() + 60
    environment = dict(os.environ)
    os.environ.clear()
    try:
        source = context(environment)
        resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
        resource.setrlimit(resource.RLIMIT_FSIZE, (8192, 8192))
        def no_children(event, args):
            need(event not in ('subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.exec', 'os.fork', 'os.forkpty'))
        sys.addaudithook(no_children)
        report = bound_observe(end, source['observerSourceSha256'])
        report.update(schemaVersion=1, kind='mrk-directory-identity-diagnostic', diagnosticWorkflow=source)
        publish(report, end)
        return 0
    except BaseException:
        print('directory-identity-probe-refused', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
