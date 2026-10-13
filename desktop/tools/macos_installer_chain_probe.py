#!/usr/bin/env python3
"""Fixed public-DER comparison, not signing, system trust or revocation proof."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path('/Users/runner/work/mobile-release-kit/mobile-release-kit')
SCRIPT = 'desktop/tools/macos_installer_chain_probe.py'
REF = 'refs/heads/verify/desktop-macos-installer-chain'
WORKFLOW = 'Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-installer-chain.yml@' + REF
SECURITY = '/usr/bin/security'
CERTIFICATES = (
    ('leaf', 1489, '76880822154a840386b3a309382069568262ad79a84611d1281b823312e9fe04'),
    ('issuer', 1090, 'f16cd3c54c7f83cea4bf1a3e6a0819c8aaa8e4a1528fd144715f350643d2df3a'),
    ('root', 1215, 'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024'),
)
LIMIT = 16384


class Refused(ValueError):
    pass


def need(value):
    if not value:
        raise Refused('installer-chain-probe-refused')


def clock(endpoint):
    need(time.monotonic() < endpoint)


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def context(environment, script, host, uid, euid, gid, egid):
    source = environment.get('GITHUB_SHA', '')
    expected = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': REF,
        'GITHUB_REPOSITORY': 'Apdelrahman1911/mobile-release-kit', 'GITHUB_WORKSPACE': str(ROOT),
        'GITHUB_WORKFLOW_REF': WORKFLOW, 'GITHUB_WORKFLOW_SHA': source,
        'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'macOS', 'RUNNER_ARCH': 'ARM64'}
    need(re.fullmatch('[0-9a-f]{40}', source) is not None and source != '0' * 40
         and all(environment.get(k) == v for k, v in expected.items())
         and Path(script).absolute() == ROOT / SCRIPT
         and host.sysname == 'Darwin' and host.machine == 'arm64'
         and type(uid) is int and uid > 0 and uid == euid and gid == egid)
    ids = [environment.get(k, '') for k in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')]
    need(all(re.fullmatch('[1-9][0-9]{0,19}', value) is not None for value in ids))
    return dict(source=source, workflowSource=source, runId=ids[0], runAttempt=ids[1],
                target='aarch64-apple-darwin')


class Original:
    def __init__(self, path, body=None):
        self.path, self.fd, self.before, self.body = Path(path), None, None, body
        self.fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            s = os.fstat(self.fd)
            need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_uid == os.getuid()
                 and not s.st_mode & 0o022 and 0 < s.st_size <= LIMIT)
            self.before = identity(s)
            observed = self.read()
            need(body is None or observed == body)
            self.body = observed
        except BaseException:
            self.close()
            raise

    def read(self):
        need(self.fd is not None and identity(os.fstat(self.fd)) == self.before
             == identity(self.path.lstat()))
        body = os.pread(self.fd, self.before[6] + 1, 0)
        need(len(body) == self.before[6] and identity(os.fstat(self.fd)) == self.before
             == identity(self.path.lstat()))
        return body

    def post(self):
        need(self.read() == self.body)

    def close(self):
        fd, self.fd = self.fd, None
        if fd is not None:
            os.close(fd)  # Consuming, never retry an uncertain close.


def command(policy, paths):
    need(policy in ('pkgSign', 'basic') and type(paths) is tuple and len(paths) == 3
         and all(isinstance(p, Path) for p in paths)
         and tuple(p.name for p in paths) == ('leaf.der', 'issuer.der', 'root.der'))
    return [SECURITY, 'verify-cert', '-p', policy, '-N', '-L',
            '-c', str(paths[0]), '-c', str(paths[1]), '-r', str(paths[2])]


def run(policy, paths, environment, endpoint):
    """Own direct child and pipes only. Popen itself is not interruptible here."""
    end = min(endpoint, time.monotonic() + 30)
    clock(end)
    process, selector, streams, primary = None, None, [], None
    outputs = [bytearray(), bytearray()]
    code = None
    try:
        process = subprocess.Popen(command(policy, paths), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, env=environment)
        # A late constructor is a refusal, never a renewed collection budget.
        clock(end)
        streams = [process.stdout, process.stderr]
        selector = selectors.DefaultSelector()
        for index, stream in enumerate(streams):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, index)
        while selector.get_map():
            clock(end)
            for key, _mask in selector.select(max(0, end - time.monotonic())):
                index = key.data
                chunk = os.read(key.fileobj.fileno(), min(4096, LIMIT + 1 - len(outputs[index])))
                if not chunk:
                    selector.unregister(key.fileobj)
                else:
                    outputs[index].extend(chunk)
                    need(len(outputs[index]) <= LIMIT)
            clock(end)
        code = process.wait(timeout=max(0, end - time.monotonic()))
        clock(end)
        need(type(code) is int and 0 <= code <= 255)
    except BaseException as error:
        primary = error
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)
            except BaseException as error:
                if primary is None:
                    primary = error
        # Popen may return after its endpoint; its streams are still owned.
        if process is not None and not streams:
            streams = [process.stdout, process.stderr]
        for item in [selector, *streams]:
            if item is not None:
                try:
                    item.close()
                except BaseException as error:
                    if primary is None:
                        primary = error
    if primary is not None:
        raise Refused('installer-chain-probe-original-unknown') from None
    return dict(policy=policy, returncode=code,
        stdoutSha256=hashlib.sha256(outputs[0]).hexdigest(),
        stderrSha256=hashlib.sha256(outputs[1]).hexdigest(),
        originalJoined=True, capturesClosed=True)


def compare(paths, environment, endpoint, post):
    results = []
    for policy in ('pkgSign', 'basic'):
        clock(endpoint)
        post()
        row = run(policy, paths, environment, endpoint)
        clock(endpoint)
        post()
        results.append(row)
    return results


def report(binding, results):
    need(type(results) is list and len(results) == 2)
    for policy, row in zip(('pkgSign', 'basic'), results):
        need(type(row) is dict and set(row) == {'policy', 'returncode', 'stdoutSha256',
             'stderrSha256', 'originalJoined', 'capturesClosed'} and row['policy'] == policy
             and type(row['returncode']) is int and 0 <= row['returncode'] <= 255
             and row['originalJoined'] is True and row['capturesClosed'] is True
             and all(type(row[k]) is str and re.fullmatch('[0-9a-f]{64}', row[k]) is not None
                     for k in ('stdoutSha256', 'stderrSha256')))
    value = dict(schemaVersion=1, kind='installer-public-chain-comparison', **binding,
        certificates={role: sha for role, _size, sha in CERTIFICATES}, originals=results,
        diagnosticComplete=True, comparisonMatched=[r['returncode'] for r in results] == [1, 0],
        inputPostMatched=True, ownedScratchRetired=True, packageSigned=False,
        systemTrustEstablished=False, revocationChecked=False, notarizationAccepted=False, productReady=False)
    body = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    need(len(body) <= 4096)
    return body


def main():
    endpoint = time.monotonic() + 90
    binding = context(os.environ, __file__, os.uname(), os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    need(Path.cwd() == ROOT and ROOT.resolve() == ROOT)
    sources, copies, scratch, identities, primary, result = [], [], None, {}, None, None
    try:
        head = Original(ROOT / '.git/HEAD')
        sources.append(head)
        need(head.body == (binding['source'] + '\n').encode('ascii'))
        for role, size, sha in CERTIFICATES:
            entry = Original(ROOT / 'desktop/packaging/macos-installer-certificates' / (role + '.der'))
            sources.append(entry)
            need(len(entry.body) == size and hashlib.sha256(entry.body).hexdigest() == sha)
        tools = []
        for path in (Path('/'), Path('/usr'), Path('/usr/bin'), Path(SECURITY)):
            s = path.lstat()
            need(s.st_uid == 0 and not s.st_mode & 0o022
                 and (stat.S_ISREG(s.st_mode) and s.st_mode & 0o111 if str(path) == SECURITY else stat.S_ISDIR(s.st_mode)))
            tools.append((path, identity(s)))
        scratch = Path(tempfile.mkdtemp(prefix='mrk-installer-public-chain.', dir='/private/tmp'))
        need(scratch.lstat().st_uid == os.getuid() and stat.S_IMODE(scratch.lstat().st_mode) == 0o700)
        identities[scratch] = identity(scratch.lstat())[:5]
        for name in ('home', 'tmp'):
            path = scratch / name
            path.mkdir(mode=0o700)
            identities[path] = identity(path.lstat())[:5]
        for (role, _size, _sha), original in zip(CERTIFICATES, sources[1:]):
            path = scratch / (role + '.der')
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                need(os.write(fd, original.body) == len(original.body))
            finally:
                os.close(fd)
            copies.append(Original(path, original.body))
        def post():
            clock(endpoint)
            for entry in sources + copies:
                entry.post()
            for path, before in tools:
                need(identity(path.lstat()) == before)
            for path, before in identities.items():
                need(identity(path.lstat())[:5] == before)
        clean = {'PATH': '/usr/bin:/bin', 'HOME': str(scratch / 'home'), 'TMPDIR': str(scratch / 'tmp'),
                 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}
        results = compare(tuple(entry.path for entry in copies), clean, endpoint, post)
        post()
        need(set(os.listdir(scratch)) == {'leaf.der', 'issuer.der', 'root.der', 'home', 'tmp'})
        need(not os.listdir(scratch / 'home') and not os.listdir(scratch / 'tmp'))
        # A source-close failure leaves the owned scratch intact, not retired.
        for entry in reversed(sources):
            entry.post()
            entry.close()
        # Only exact owned public files; no recursive removal or unknown reuse.
        for entry in reversed(copies):
            entry.post()
            entry.path.unlink()
            need(os.fstat(entry.fd).st_nlink == 0)
            entry.close()
        for path in (scratch / 'tmp', scratch / 'home', scratch):
            need(identity(path.lstat())[:5] == identities[path])
            path.rmdir()
        clock(endpoint)
        result = report(binding, results)
    except BaseException as error:
        primary = error
    finally:
        for entry in reversed(sources + copies):
            try:
                entry.close()
            except BaseException as error:
                if primary is None:
                    primary = error
    if primary is not None:
        raise Refused('installer-chain-probe-incomplete') from None
    sys.stdout.buffer.write(result)
    sys.stdout.buffer.flush()


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        sys.stderr.write('installer-chain diagnostic incomplete; no qualification claimed\n')
        raise SystemExit(1) from None
