"""Temporary ARM compiler-diagnostic encryption, never a signing/build retry.

Only the public recipient travels to the runner. Plaintext stays in memory;
only a known-settled CMS ciphertext and finite transport receipt may be uploaded.
CMS confidentiality does not authenticate the GitHub source/artifact transport.
"""
import base64
import hashlib
import json
import os
import re
import resource
import signal
import stat
import subprocess
import sys
import time

REF = 'refs/heads/verify/desktop-macos-app-signature'
REPOSITORY = 'Apdelrahman1911/mobile-release-kit'
CHECKOUT = '/Users/runner/work/mobile-release-kit/mobile-release-kit'
RECIPIENT = 'desktop/macos-installed-inputs/resident-compiler-diagnostic-recipient.pem'
RECIPIENT_SHA = '4490cfbef46f588caea1034495297a2df37d8155d4b6988fafd7472277728af4'
RAW_LIMIT = 4 * 1024 * 1024
PLAIN_LIMIT = 6 * 1024 * 1024
CIPHER_LIMIT = 8 * 1024 * 1024
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC


def need(ok):
    if not ok:
        raise ValueError('confidential-compiler-capture-refused')


def sha(body):
    return hashlib.sha256(body).hexdigest()


def identity(value, directory=False):
    fixed = (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
             getattr(value, 'st_flags', 0))
    return fixed if directory else fixed + (value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result


def receipt_data(body, context):
    value = json.loads(body, object_pairs_hook=unique,
                       parse_constant=lambda value: need(False))
    need(type(value) is dict and type(value.get('schemaVersion')) is int and value['schemaVersion'] == 1)
    for key in ('source', 'workflowSource', 'workflow', 'runId', 'runAttempt', 'target'):
        need(value.get(key) == context[key])
    need(value.get('phase') == 'prepare' and value.get('packageRole') == 'ordinary-image')
    need(value.get('toolchain') == '1.98.1')
    for key in ('targetRetired', 'originalClosesKnown', 'outerFinalityRequired'):
        need(value.get(key) is True)
    for key in ('passed', 'androidServiceAuthenticated', 'androidRegisteredCopyQualified',
                'androidBuildQualified', 'developerIdOrNotarizationQualified', 'productReady'):
        need(value.get(key) is False)
    for key in ('credentialOriginals', 'credentialContexts', 'cleanupErrors'):
        need(type(value.get(key)) is list and not value[key])
    need('directStagerIOPending' in value and value['directStagerIOPending'] is None)
    need(value.get('failure') == {'stage': 'separate-resident-image-compiler',
                                 'type': 'Refused', 'reason': 'original-nonzero-build'})
    calls = value.get('originalCalls')
    need(type(calls) is list and len(calls) == 1 and type(calls[0]) is dict)
    call = calls[0]
    need(set(call) == {'role', 'entered', 'returned', 'capturesSettled', 'returncode',
                      'stdoutSha256', 'stderrSha256'})
    need(call['role'] == 'build' and all(call[key] is True for key in ('entered', 'returned', 'capturesSettled')))
    need(type(call['returncode']) is int and call['returncode'] == 101)
    need(all(type(call[key]) is str and re.fullmatch('[0-9a-f]{64}', call[key])
             for key in ('stdoutSha256', 'stderrSha256')))
    return value, call


def child_limits():
    # This single ordinary OpenSSL child has no inherited signing environment.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (CIPHER_LIMIT, CIPHER_LIMIT))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    start = time.monotonic()
    def tick():
        need(time.monotonic() - start <= 60)
    need(sys.platform == 'darwin' and os.getuid() != 0 and os.getuid() == os.geteuid())
    env = os.environ
    need(not any(key in env for key in ('MRK_MACOS_DEVELOPER_ID_P12_BASE64',
        'MRK_MACOS_DEVELOPER_ID_P12_PASSWORD', 'MRK_MACOS_NOTARY_API_KEY_BASE64')))
    need(env.get('GITHUB_REPOSITORY') == REPOSITORY and env.get('GITHUB_REF') == REF
         and env.get('GITHUB_EVENT_NAME') == 'push' and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
         and env.get('RUNNER_OS') == 'macOS' and env.get('RUNNER_ARCH') == 'ARM64'
         and env.get('MRK_MACOS_TARGET') == 'aarch64-apple-darwin'
         and env.get('GITHUB_WORKSPACE') == CHECKOUT)
    source = env.get('GITHUB_SHA', '')
    need(re.fullmatch('[0-9a-f]{40}', source) and source != '0' * 40
         and env.get('MRK_EXPECTED_SHA') == source and env.get('GITHUB_WORKFLOW_SHA') == source
         and env.get('MRK_MACOS_INSTALL_SOURCE_COMMIT') == source)
    workflow = REPOSITORY + '/.github/workflows/desktop-macos-installed.yml@' + REF
    need(env.get('GITHUB_WORKFLOW_REF') == workflow)
    run, attempt = env.get('GITHUB_RUN_ID', ''), env.get('GITHUB_RUN_ATTEMPT', '')
    need(all(re.fullmatch('[1-9][0-9]{0,15}', value) and int(value) <= 9007199254740991
             for value in (run, attempt)))
    work = env.get('MRK_MACOS_WORK', '')
    need(re.fullmatch('/Users/runner/work/_temp/mrk-macos-installed\\.[A-Za-z0-9]{8}', work))
    context = dict(source=source, workflowSource=source, workflow=workflow,
                   runId=run, runAttempt=attempt, target='aarch64-apple-darwin')
    # Fixed nofollow chains and original descriptors remain held through POST.
    originals = []
    directories = {}
    def directory(path):
        if path in directories:
            return directories[path]
        parent_path, name = os.path.split(path)
        parent = None if path == '/' else directory(parent_path or '/')
        fd = os.open('/' if parent is None else name, FLAGS | os.O_DIRECTORY, dir_fd=parent)
        originals.append([fd, parent, '/' if parent is None else name, None, True])
        info = os.fstat(fd)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid()))
        originals[-1][3] = identity(info, True)
        directories[path] = fd
        return fd
    def read_file(path, limit, private):
        tick()
        parent_path, name = os.path.split(path)
        parent = directory(parent_path)
        fd = os.open(name, FLAGS | os.O_NONBLOCK, dir_fd=parent)
        originals.append([fd, parent, name, None, False])
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
             and stat.S_IMODE(before.st_mode) in ((0o600,) if private else (0o444, 0o644))
             and 0 <= before.st_size <= limit)
        originals[-1][3] = identity(before)
        parts, remaining = [], before.st_size
        while remaining:
            tick()
            part = os.read(fd, min(65536, remaining))
            need(part)
            parts.append(part)
            remaining -= len(part)
        need(os.read(fd, 1) == b'')
        need(identity(os.fstat(fd)) == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(before))
        return fd, b''.join(parts)
    output_fd = cipher_fd = None
    child = None
    try:
        work_fd = directory(work)
        need(stat.S_IMODE(os.fstat(work_fd).st_mode) == 0o700 and os.fstat(work_fd).st_uid == os.getuid())
        try:
            os.stat('android-helper-target', dir_fd=work_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            need(False)
        _, receipt_body = read_file(work + '/android-helper-prepare.json', 16384, True)
        receipt, call = receipt_data(receipt_body, context)
        _, stdout = read_file(work + '/android-helper-build.jsonl', RAW_LIMIT, True)
        _, stderr = read_file(work + '/android-helper-build.stderr', RAW_LIMIT - len(stdout), True)
        need(sha(stdout) == call['stdoutSha256'] and sha(stderr) == call['stderrSha256'])
        cert_fd, certificate = read_file(CHECKOUT + '/' + RECIPIENT, 16384, False)
        need(len(certificate) == 1554 and sha(certificate) == RECIPIENT_SHA)
        os.lseek(cert_fd, 0, os.SEEK_SET)
        payload = json.dumps(dict(schemaVersion=1, context=context, helperReceipt=receipt,
            stdoutBase64=base64.b64encode(stdout).decode('ascii'),
            stderrBase64=base64.b64encode(stderr).decode('ascii')),
            sort_keys=True, separators=(',', ':')).encode('ascii')
        need(len(payload) <= PLAIN_LIMIT)
        raw_bytes, stdout_bytes, stderr_bytes = len(stdout) + len(stderr), len(stdout), len(stderr)
        del stdout, stderr, receipt, certificate
        # Fixed root-owned system CLI, no PATH lookup or tool installation.
        tool = os.stat('/usr/bin/openssl', follow_symlinks=False)
        need(stat.S_ISREG(tool.st_mode) and tool.st_uid == 0 and tool.st_mode & 0o111
             and not tool.st_mode & 0o022)
        os.mkdir('resident-compiler-confidential', 0o700, dir_fd=work_fd)
        output_fd = os.open('resident-compiler-confidential', FLAGS | os.O_DIRECTORY, dir_fd=work_fd)
        output_identity = identity(os.fstat(output_fd), True)
        cipher_fd = os.open('cargo-capture.cms', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                            0o600, dir_fd=output_fd)
        argv = ['/usr/bin/openssl', 'cms', '-encrypt', '-aes256', '-binary', '-outform', 'DER',
                '/dev/fd/' + str(cert_fd)]
        tick()
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=cipher_fd, stderr=subprocess.DEVNULL,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'OPENSSL_CONF': '/dev/null'},
            cwd='/', close_fds=True, pass_fds=(cert_fd,), start_new_session=True, preexec_fn=child_limits)
        try:
            child.communicate(payload, timeout=min(30, max(0.001, 55 - (time.monotonic() - start))))
        except BaseException:
            try:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            finally:
                child.wait(timeout=5)
            raise
        finally:
            if child.stdin is not None and not child.stdin.closed:
                child.stdin.close()
        need(child.returncode == 0 and child.stdin is not None and child.stdin.closed)
        del payload
        tick()
        os.fsync(cipher_fd)
        before = os.fstat(cipher_fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
             and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= CIPHER_LIMIT)
        ciphertext_hash = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            tick()
            block = os.pread(cipher_fd, min(65536, before.st_size - offset), offset)
            need(block)
            ciphertext_hash.update(block)
            offset += len(block)
        need(os.pread(cipher_fd, 1, offset) == b'' and identity(os.fstat(cipher_fd)) == identity(before)
             == identity(os.stat('cargo-capture.cms', dir_fd=output_fd, follow_symlinks=False)))
        need(identity(os.stat('/usr/bin/openssl', follow_symlinks=False)) == identity(tool))
        for fd, parent, name, expected, is_directory in originals:
            tick()
            need(expected is not None and identity(os.fstat(fd), is_directory) == expected
                 == identity(os.stat(name, dir_fd=parent, follow_symlinks=False), is_directory))
        need(identity(os.fstat(output_fd), True) == output_identity
             == identity(os.stat('resident-compiler-confidential', dir_fd=work_fd, follow_symlinks=False), True))
        closed_cipher, cipher_fd = cipher_fd, None
        os.close(closed_cipher)
        # Consume every input/parent original before publishing the public DATA.
        while originals:
            fd = originals.pop()[0]
            os.close(fd)
        transport = dict(schemaVersion=1, purpose='confidential-resident-compiler-diagnostic', **context,
            helperReturncode=101, originalBuildReturned=True, originalCapturesSettled=True,
            targetRetired=True, inputClosesKnown=True, credentialOperations=0, credentialContexts=0,
            recipientSha256=RECIPIENT_SHA, helperReceiptSha256=sha(receipt_body),
            stdoutBytes=stdout_bytes, stderrBytes=stderr_bytes, rawCaptureBytes=raw_bytes,
            stdoutSha256=call['stdoutSha256'], stderrSha256=call['stderrSha256'],
            ciphertextBytes=before.st_size, ciphertextSha256=ciphertext_hash.hexdigest(),
            encryption='CMS-AES256-CBC-RSA3072', encryptionReturncode=0, encryptionOriginalJoined=True,
            encryptionInputClosed=True, ciphertextClosed=True, publicationRequiresZeroExit=True,
            authenticatesOrigin=False, buildPassed=False, signingAttempted=False)
        body = (json.dumps(transport, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
        need(len(body) <= 4096)
        fd = os.open('receipt.json', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=output_fd)
        try:
            need(os.write(fd, body) == len(body))
            os.fsync(fd)
            info = os.fstat(fd)
            need(os.pread(fd, len(body) + 1, 0) == body
                 and identity(os.fstat(fd)) == identity(info)
                 == identity(os.stat('receipt.json', dir_fd=output_fd, follow_symlinks=False))
                 and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                 and stat.S_IMODE(info.st_mode) == 0o600)
        finally:
            os.close(fd)
        need(set(os.listdir(output_fd)) == {'cargo-capture.cms', 'receipt.json'})
        tick()
    finally:
        # No retry of a descriptor whose close outcome became uncertain.
        failed_close = False
        remaining = ([cipher_fd] if cipher_fd is not None else [])
        cipher_fd = None
        while originals:
            remaining.append(originals.pop()[0])
        if output_fd is not None:
            remaining.append(output_fd)
            output_fd = None
        for fd in remaining:
            try:
                os.close(fd)
            except OSError:
                failed_close = True
        need(not failed_close)


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        # Neither private compiler bytes nor subprocess/OS exception text escape.
        try:
            sys.stderr.write('Confidential compiler capture refused; no plaintext fallback.\n')
        except BaseException:
            pass
        raise SystemExit(1)
