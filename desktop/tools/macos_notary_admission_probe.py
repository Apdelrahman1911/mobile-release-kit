#!/usr/bin/env python3
"""Fixed read-only hosted metadata observation; no tool execution or credentials."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

ROOT = Path('/Users/runner/work/mobile-release-kit/mobile-release-kit')
SCRIPT = 'desktop/tools/macos_notary_admission_probe.py'
HELPER = 'desktop/tools/macos_android_helper_package.py'
REF = 'refs/heads/verify/desktop-macos-notary-admission'
WORKFLOW = 'Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-notary-admission.yml@' + REF
SOURCE_LIMIT = 1024 * 1024
OUTPUT_LIMIT = 32768
METHODS = ('register', 'close', 'notary_tool', 'notary_tool_post')
REASONS = frozenset(('notary-fixed-tool', 'install-product-fixed-tool',
    'notary-selected-tool-path', 'notary-selected-tool-ancestry',
    'notary-selected-tool-original', 'notary-selected-tool-changed'))


class ProbeRefused(ValueError):
    pass


def require(value):
    if not value:
        raise ProbeRefused('fixed-probe-refused')


def clock(deadline):
    require(type(deadline) is int and time.monotonic_ns() < deadline)


def context(environment, script, host, uid, euid, gid, egid):
    source = environment.get('GITHUB_SHA', '')
    required = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': REF,
        'GITHUB_REPOSITORY': 'Apdelrahman1911/mobile-release-kit', 'GITHUB_WORKSPACE': str(ROOT),
        'GITHUB_WORKFLOW_REF': WORKFLOW, 'GITHUB_WORKFLOW_SHA': source,
        'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'macOS', 'RUNNER_ARCH': 'ARM64'}
    require(re.fullmatch('[0-9a-f]{40}', source) is not None and source != '0' * 40
        and all(environment.get(k) == v for k, v in required.items())
        and Path(script).absolute() == ROOT / SCRIPT
        and host.sysname == 'Darwin' and host.machine == 'arm64'
        and type(uid) is int and uid > 0 and uid == euid and gid == egid)
    identifiers = [environment.get(key, '') for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')]
    require(all(re.fullmatch('[1-9][0-9]{0,15}', value) is not None
        and int(value) <= 9007199254740991 for value in identifiers))
    return {'source': source, 'workflowSource': source, 'runId': identifiers[0],
        'runAttempt': identifiers[1], 'target': 'aarch64-apple-darwin',
        'binding': 'current-checkout-context-and-observed-helper-bytes-only'}


def source_bytes(path, deadline):
    clock(deadline)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= SOURCE_LIMIT)
        body = bytearray()
        while len(body) <= SOURCE_LIMIT:
            clock(deadline)
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
        os.close(fd)  # No retry after uncertain close; a failure prevents a report.


def load_tools(body):
    """Only the genuine fixed metadata methods; no product initializer/import."""
    require(type(body) is bytes and 0 < len(body) <= SOURCE_LIMIT)
    tree = ast.parse(body)
    names = ('READ_FLAGS', 'NOTARY_XCODE', 'Refused', 'need', 'signature')
    selected = []
    for name in names:
        matches = [node for node in tree.body if getattr(node, 'name', None) == name
            or isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
        require(len(matches) == 1)
        selected.append(matches[0])
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Operation']
    require(len(classes) == 1)
    methods = []
    for name in METHODS:
        matches = [node for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name == name]
        require(len(matches) == 1)
        methods.append(matches[0])
    selected.append(ast.ClassDef(name='FixedTools', bases=[], keywords=[], body=methods, decorator_list=[]))
    namespace = {'Path': Path, 'os': os, 'stat': stat}
    exec(compile(ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])),
        '<current-fixed-notary-metadata>', 'exec'), namespace)
    return namespace


def failure(error, refused):
    if type(error) is refused:
        reason = error.args[0] if len(error.args) == 1 else None
        return {'state': 'refused', 'reason': reason if type(reason) is str and reason in REASONS else 'unclassified', 'errno': None}
    if isinstance(error, OSError):
        number = OSError.errno.__get__(error)
        return {'state': 'os-error', 'reason': 'os-error',
            'errno': number if type(number) is int and 0 < number < 65536 else None}
    raise ProbeRefused('fixed-probe-refused') from None


def census(namespace, name, deadline):
    """Later metadata only, kept separate from the genuine call's first result."""
    clock(deadline)
    xcode = namespace['NOTARY_XCODE']
    fixed = xcode / 'usr/bin' / name
    canonical = fixed.resolve(strict=True)
    applications = xcode.parents[2]
    require(canonical.is_absolute() and len(canonical.parts) <= 16
        and applications.resolve(strict=True) in canonical.parents)
    paths = sorted({fixed, canonical, *fixed.parents, *canonical.parents},
        key=lambda item: (len(item.parts), str(item)))
    require(len(paths) <= 32)
    rows = []
    for ordinal, path in enumerate(paths):
        clock(deadline)
        info = path.lstat()
        alias = stat.S_ISLNK(info.st_mode) and path == xcode.parent.parent
        above = path in applications.parents
        directory, regular, symlink = stat.S_ISDIR(info.st_mode), stat.S_ISREG(info.st_mode), stat.S_ISLNK(info.st_mode)
        root, current = info.st_uid == 0, info.st_uid == os.getuid()
        group_write, other_write = bool(info.st_mode & 0o020), bool(info.st_mode & 0o002)
        trusted_applications_group = (path == applications and directory and root
            and info.st_gid in (0, 80) and not other_write)
        role = ('root' if path == Path('/') else 'applications' if path == applications else
            'xcode-alias' if path == xcode.parent.parent else 'fixed-tool' if path == fixed else
            'canonical-tool' if path == canonical else 'above-applications' if above else 'other-ancestor')
        rows.append({'ordinal': ordinal, 'role': role, 'ownerIsRoot': root, 'ownerIsCurrent': current,
            'groupIsRootOrAdmin': info.st_gid in (0, 80), 'directory': directory, 'regular': regular,
            'symlink': symlink, 'selectedAlias': alias, 'aboveApplications': above,
            'groupWritable': group_write, 'otherWritable': other_write,
            'predicateAccepted': (root or current) and (alias or (directory or regular)
                and (above or not (group_write or other_write) or trusted_applications_group))})
    clock(deadline)
    return rows


def observe(namespace, deadline):
    operation = namespace['FixedTools']()
    operation.entries, operation.entry_registry = [], {}
    operation.errors, operation.notary_tools = [], {}
    rows = []
    try:
        for name in ('notarytool', 'stapler'):
            clock(deadline)
            require(len(operation.entries) <= 1)
            row = {'tool': name, 'toolAdmissionPassed': False, 'admission': None,
                'laterCensus': None, 'post': None}
            try:
                operation.notary_tool(name)
                row['admission'] = {'state': 'admitted', 'reason': None, 'errno': None}
                row['toolAdmissionPassed'] = True
            except BaseException as error:
                row['admission'] = failure(error, namespace['Refused'])
            clock(deadline)
            try:
                row['laterCensus'] = {'state': 'observed', 'rows': census(namespace, name, deadline)}
            except ProbeRefused:
                row['laterCensus'] = {'state': 'unavailable', 'rows': []}
            except OSError as error:
                row['laterCensus'] = {**failure(error, namespace['Refused']), 'rows': []}
            # POST has its own result and cannot replace the first refusal.
            if name in operation.notary_tools:
                try:
                    clock(deadline)
                    operation.notary_tool_post(operation.notary_tools[name])
                    row['post'] = {'state': 'observed', 'reason': None, 'errno': None}
                except BaseException as error:
                    row['post'] = failure(error, namespace['Refused'])
            rows.append(row)
    finally:
        for entry in reversed(operation.entries):
            operation.close(entry)
        require(not operation.errors and all(entry['closed'] and entry['fd'] is None for entry in operation.entries))
    clock(deadline)
    require(len(rows) == 2 and len(operation.entries) <= 2)
    return {'tools': rows, 'registeredToolDescriptors': len(operation.entries), 'toolDescriptorsClosed': True,
        'diagnosticCompleted': True, 'assurance': 'readonly-host-metadata-not-payload-authentication-or-notarization'}


def encode(report):
    body = (json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
    require(0 < len(body) <= OUTPUT_LIMIT)
    return body


def main():
    try:
        deadline = time.monotonic_ns() + 60_000_000_000
        admitted = context(os.environ, __file__, os.uname(), os.getuid(), os.geteuid(), os.getgid(), os.getegid())
        body = source_bytes(ROOT / HELPER, deadline)
        namespace = load_tools(body)
        result = observe(namespace, deadline)
        report = {'schemaVersion': 1, **admitted, 'helperSha256': hashlib.sha256(body).hexdigest(),
            'sourceDescriptorClosed': True, **result}
        output = encode(report)
        clock(deadline)
        written = sys.stdout.buffer.write(output)
        require(written == len(output))
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        try:
            sys.stderr.write('Fixed notary metadata diagnostic unavailable; no raw evidence emitted.\n')
        except BaseException:
            pass
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
