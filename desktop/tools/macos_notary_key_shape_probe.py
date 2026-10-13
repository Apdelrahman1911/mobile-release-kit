#!/usr/bin/env python3
"""Fixed hosted DATA-only shape observation; never key validity or authentication."""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

ROOT = Path('/home/runner/work/mobile-release-kit/mobile-release-kit')
SCRIPT = 'desktop/tools/macos_notary_key_shape_probe.py'
HELPER = 'desktop/tools/macos_android_helper_package.py'
VARIABLE = 'MRK_MACOS_NOTARY_API_KEY_BASE64'
REF = 'refs/heads/verify/desktop-macos-notary-key-shape'
WORKFLOW = 'Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-notary-key-shape.yml@' + REF
SOURCE_LIMIT = 1024 * 1024
OUTPUT_LIMIT = 4096
REASONS = frozenset(('notary-key-input', 'notary-key-base64', 'notary-key-pem-shape'))


class ProbeRefused(ValueError):
    pass


def require(value):
    if not value:
        raise ProbeRefused('fixed-key-shape-probe-refused')


def context(environment, script, host, uid, euid, gid, egid):
    source = environment.get('GITHUB_SHA', '')
    expected = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': REF,
        'GITHUB_REPOSITORY': 'Apdelrahman1911/mobile-release-kit', 'GITHUB_WORKSPACE': str(ROOT),
        'GITHUB_WORKFLOW_REF': WORKFLOW, 'GITHUB_WORKFLOW_SHA': source,
        'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux', 'RUNNER_ARCH': 'X64'}
    require(type(source) is str and re.fullmatch('[0-9a-f]{40}', source) is not None
        and source != '0' * 40 and all(environment.get(k) == v for k, v in expected.items())
        and Path(script).absolute() == ROOT / SCRIPT
        and host.sysname == 'Linux' and host.machine == 'x86_64'
        and all(type(value) is int for value in (uid, euid, gid, egid))
        and uid > 0 and uid == euid and gid >= 0 and gid == egid)
    identifiers = [environment.get(key, '') for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')]
    require(all(type(value) is str and re.fullmatch('[1-9][0-9]{0,15}', value) is not None
        and int(value) <= 9007199254740991 for value in identifiers))
    return {'source': source, 'workflowSource': source, 'runId': identifiers[0],
        'runAttempt': identifiers[1], 'binding': 'current-checkout-context-and-observed-helper-bytes-only'}


def source_bytes(path, deadline):
    require(time.monotonic_ns() < deadline)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= SOURCE_LIMIT)
        body = bytearray()
        while len(body) <= SOURCE_LIMIT:
            require(time.monotonic_ns() < deadline)
            chunk = os.read(fd, min(65536, SOURCE_LIMIT + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        after = os.fstat(fd)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        require(len(body) == before.st_size and identity(before) == identity(after)
            == identity(os.stat(path, follow_symlinks=False)))
        return bytes(body)
    finally:
        os.close(fd)  # Uncertain close prevents a completed report; never retry.


def load_parser(body):
    require(type(body) is bytes and 0 < len(body) <= SOURCE_LIMIT)
    tree = ast.parse(body)
    selected = []
    for name in ('NOTARY_KEY_VARIABLE', 'Refused', 'need', 'notary_key_data'):
        matches = [node for node in tree.body if getattr(node, 'name', None) == name
            or isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
        require(len(matches) == 1)
        selected.append(matches[0])
    require(isinstance(selected[0], ast.Assign)
        and isinstance(selected[0].value, ast.Constant) and selected[0].value.value == VARIABLE)
    namespace = {'base64': base64, 're': re}
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<current-notary-key-data>', 'exec'), namespace)
    return namespace


def newline_compatibility(namespace, value):
    """Supplementary compatibility only; never substitutes for the original input."""
    try:
        require(type(value) is str and 4 <= len(value) <= 10924 and value.isascii())
        body = base64.b64decode(value, validate=True)
        require(0 < len(body) <= 8192 and body.isascii() and b'\0' not in body
            and base64.b64encode(body).decode('ascii') == value)
        crlf, missing_lf = b'\r\n' in body, not body.endswith(b'\n')
        for label in ('crlf-only', 'terminal-lf-only', 'crlf-and-terminal-lf'):
            if label == 'crlf-only' and crlf:
                candidate = body.replace(b'\r\n', b'\n')
            elif label == 'terminal-lf-only' and missing_lf:
                candidate = body + b'\n'
            elif label == 'crlf-and-terminal-lf' and crlf and missing_lf:
                candidate = body.replace(b'\r\n', b'\n') + b'\n'
            else:
                continue
            try:
                namespace['notary_key_data']({VARIABLE: base64.b64encode(candidate).decode('ascii')})
            except namespace['Refused']:
                continue
            return label
        return 'no-match'
    except BaseException:
        return 'not-evaluated'  # No supplementary exception can replace the first result.


def observe(namespace, value):
    reason = None
    try:
        namespace['notary_key_data']({VARIABLE: value})
    except namespace['Refused'] as error:
        reason = error.args[0] if len(error.args) == 1 else None
        require(type(reason) is str and reason in REASONS)
    return {'keyShapeAccepted': reason is None, 'reason': reason,
        'newlineCompatibility': newline_compatibility(namespace, value)
            if reason == 'notary-key-pem-shape' else 'not-evaluated'}


def main():
    try:
        metadata = context(os.environ, __file__, os.uname(), os.getuid(), os.geteuid(), os.getgid(), os.getegid())
        deadline = time.monotonic_ns() + 60_000_000_000
        body = source_bytes(ROOT / HELPER, deadline)
        namespace = load_parser(body)
        value = os.environ.pop(VARIABLE, None)
        try:
            observation = observe(namespace, value)
        finally:
            value = None  # Reference dropping only, not secure memory erasure.
        require(time.monotonic_ns() < deadline)
        report = {'schemaVersion': 1, 'kind': 'notary-key-shape-data-only', **metadata,
            'helperSourceSha256': hashlib.sha256(body).hexdigest(), 'diagnosticCompleted': True,
            **observation, 'authenticationAttempted': False, 'keyFileCreated': False}
        output = json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n'
        require(len(output.encode('ascii')) <= OUTPUT_LIMIT)
        require(sys.stdout.write(output) == len(output))
        sys.stdout.flush()
        return 0
    except BaseException:
        try:
            sys.stderr.write('Fixed notary key-shape diagnostic incomplete; no authentication attempted.\n')
        except BaseException:
            pass
        return 1
    finally:
        os.environ.pop(VARIABLE, None)


if __name__ == '__main__':
    raise SystemExit(main())
