#!/usr/bin/env python3
"""Read-only, finite Apple log projection after a failed hosted service test.

This cannot register, approve, remove, launch or qualify a service. It never
exports raw log messages, arbitrary paths or NSError descriptions.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

LIMIT = 256 * 1024
IDS = ('dev.mobile-release-kit.desktop', 'dev.mobile-release-kit.desktop.android-register')
OUTER = '/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app'
INNER = OUTER + '/Contents/Helpers/MobileReleaseKitPayload.app'
PLIST = '/Contents/Library/LaunchDaemons/' + IDS[1] + '.plist'
PATHS = {'outer-plist': OUTER + PLIST, 'payload-plist': INNER + PLIST,
         'payload-helper': INNER + '/Contents/Helpers/mrk-android-register',
         'payload-bundle': INNER, 'outer-bundle': OUTER}
DOMAINS = {'SMAppServiceErrorDomain': 'smappservice', 'NSOSStatusErrorDomain': 'osstatus',
           'NSCocoaErrorDomain': 'cocoa', 'NSPOSIXErrorDomain': 'posix'}
WORDS = ('notfound', 'missing', 'failed', 'cannot', 'unable', 'error', 'register',
         'registration', 'plist', 'executable', 'bundleprogram', 'bundle', 'file',
         'path', 'url', 'service', 'responsibility', 'signature', 'approval',
         'permission', 'not', 'no', 'found', 'find', 'open', 'load', 'resolve', 'lookup')
SUBSYSTEMS = ('com.apple.backgroundtaskmanagement', 'com.apple.xpc.smd')
SMD_PATHS = ('/usr/libexec/smd', '/System/Library/PrivateFrameworks/ServiceManagement.framework/Support/smd')


def need(value):
    if not value:
        raise ValueError('service-log-data')


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result)
        result[key] = value
    return result


def project(body):
    need(type(body) is bytes and 0 < len(body) <= LIMIT)
    def constant(_value):
        raise ValueError('service-log-data')
    rows = json.loads(body.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    need(type(rows) is list and len(rows) <= 512)
    own = r'(?<![\w.-])(?:' + '|'.join(map(re.escape, IDS)) + r')(?![\w.-])'
    code_pattern = (r'(?<!\w)Domain=(' + '|'.join(map(re.escape, DOMAINS))
                    + r') Code=(-?(?:0|[1-9][0-9]{0,9}))(?=$|[^\w.+-])')
    path_patterns = {label: r'(?<![^\s\"\'(<\[{=])(?:'
        + re.escape(path) + '|' + re.escape('file://' + path.replace(' ', '%20'))
        + r')/?(?![^\s\"\')>\]},;])' for label, path in PATHS.items()}
    details = []
    matched = 0
    for row in rows:
        need(type(row) is dict and type(row.get('eventMessage')) is str
             and len(row['eventMessage']) <= 8192)
        if (row.get('subsystem') not in SUBSYSTEMS and row.get('process') != 'smd'
                and row.get('processImagePath') not in SMD_PATHS):
            continue
        message = row['eventMessage']
        paths = [label for label, pattern in path_patterns.items() if re.search(pattern, message)]
        if not re.search(own, message) and not paths:
            continue
        matched += 1
        codes = set()
        for domain, raw in re.findall(code_pattern, message):
            value = int(raw)
            if str(value) == raw and -(1 << 31) <= value < (1 << 31):
                codes.add((DOMAINS[domain], value))
        need(len(codes) <= 8)
        words = re.findall(r'(?<!\w)(?ai:' + '|'.join(WORDS) + r')(?!\w)', message)
        if len(details) < 16:
            details.append({'pathsMentioned': paths,
                'errorCodes': [{'domain': domain, 'code': code} for domain, code in sorted(codes)],
                'wordsMentionedInOrder': [word.lower() for word in words[:24]]})
    return {'state': 'observed' if matched else 'empty', 'matchingEvents': matched,
            'details': details, 'detailsOmitted': matched - len(details)}


def collect(run_owned, environment, root):
    predicate = ('(subsystem == "com.apple.backgroundtaskmanagement" OR '
        'subsystem == "com.apple.xpc.smd" OR process == "smd") AND '
        '(eventMessage CONTAINS "dev.mobile-release-kit.desktop" OR '
        'eventMessage CONTAINS "MobileReleaseKitPayload.app" OR '
        'eventMessage CONTAINS "Mobile Release Kit.app")')
    argv = ['/usr/bin/log', 'show', '--last', '5m', '--style', 'json', '--info', '--debug',
            '--no-pager', '--predicate', predicate]
    report = {'schemaVersion': 1, 'kind': 'macos-tool-service-log-diagnostic',
              'diagnosticOnly': True, 'serviceQualified': False, 'originalCallReturned': False}
    try:
        result = run_owned(argv, environ=environment, cwd=root, timeout=25,
                           capture=True, text=False, output_limit=LIMIT)
        need(type(result) is subprocess.CompletedProcess and result.args == argv
             and type(result.returncode) is int and type(result.stdout) is bytes
             and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= LIMIT)
        report.update(originalCallReturned=True, returncode=result.returncode)
        if result.returncode:
            return dict(report, state='call-failed')
        try:
            return dict(report, **project(result.stdout))
        except (ValueError, UnicodeError, RecursionError):
            return dict(report, state='unparseable')
    except Exception:
        # A diagnostic failure cannot rewrite the original service result.
        return dict(report, state='call-unknown')


def background_tasks(body, current_uid):
    """Finite persistent BTM records, never a fresh SMAppService observation.

    Apple can retain a disabled/pending record after unregister succeeds. These
    records explain an approval prerequisite; they cannot prove registration,
    launch eligibility, current service status or successful cleanup.
    """
    need(type(body) is bytes and 0 < len(body) <= LIMIT
         and type(current_uid) is int and 0 < current_uid < (1 << 31))
    lines = body.decode('utf-8').splitlines()
    need(len(lines) <= 8192 and all(len(line) <= 8192 for line in lines))
    result = []
    fields = {}
    scope = None
    active = False
    headers = 0
    own = '16.' + IDS[1]
    relevant = ('Identifier', 'Type', 'Disposition', 'URL', 'Executable Path', 'Parent Identifier')

    def finish():
        if own not in fields.get('Identifier', []):
            return
        need(active and scope is not None and len(result) < 16
             and all(len(fields.get(key, [])) == 1 for key in relevant))
        need(fields['Identifier'] == [own] and fields['Type'] == ['daemon (0x10)'])
        match = re.fullmatch(r'\[([^\[\]]+)\]( \(pending authorization\))? \(0x([0-9a-f]{1,8})\)',
                             fields['Disposition'][0])
        need(match is not None)
        words = match[1].split(', ')
        need(len(words) == 3 and words[0] in ('enabled', 'disabled')
             and words[1] in ('allowed', 'disallowed') and words[2] in ('notified', 'not notified'))
        plist = 'Contents/Library/LaunchDaemons/' + IDS[1] + '.plist'
        executable = 'Contents/Helpers/mrk-android-register'
        result.append({'scope': scope, 'type': 'daemon',
            'disposition': [word.replace(' ', '-') for word in words],
            'pendingAuthorization': match[2] is not None, 'dispositionBits': int(match[3], 16),
            'plist': 'payload-relative-match' if fields['URL'][0] == plist else
                'payload-absolute-match' if fields['URL'][0] == INNER + '/' + plist else 'other',
            'executable': 'payload-relative-match' if fields['Executable Path'][0] == executable else
                'payload-absolute-match' if fields['Executable Path'][0] == INNER + '/' + executable else 'other',
            'parent': 'payload-identifier-match' if fields['Parent Identifier'][0] == '2.' + IDS[0] else 'other'})

    for line in lines:
        header = re.fullmatch(r'\s*Records for UID (-?(?:0|[1-9][0-9]{0,9})) : [0-9A-Fa-f-]{36}\s*', line)
        if header:
            finish()
            uid = int(header[1])
            need(-2 <= uid < (1 << 31))
            headers += 1
            scope = 'system' if uid == -2 else 'root' if uid == 0 else 'current-user' if uid == current_uid else 'other-user'
            fields = {}
            active = False
        elif re.fullmatch(r'\s*#[1-9][0-9]{0,5}:\s*', line):
            finish()
            fields = {}
            active = True
        elif active:
            field = re.fullmatch(r'\s*([^:]+): (.*)', line)
            if field and field[1] in relevant:
                fields.setdefault(field[1], []).append(field[2])
    finish()
    need(headers > 0)
    return {'state': 'observed' if result else 'empty', 'matchingRecords': len(result), 'records': result,
            'persistentRecordsOnly': True, 'recordsMayRemainAfterUnregister': True,
            'serviceQualified': False}


def collect_background_tasks(run_owned, environment, root, current_uid):
    argv = ['/usr/bin/sfltool', 'dumpbtm']
    report = {'diagnosticOnly': True, 'serviceQualified': False, 'originalCallReturned': False}
    try:
        result = run_owned(argv, environ=environment, cwd=root, timeout=20,
                           capture=True, text=False, output_limit=LIMIT)
        need(type(result) is subprocess.CompletedProcess and result.args == argv
             and type(result.returncode) is int and type(result.stdout) is bytes
             and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= LIMIT)
        report.update(originalCallReturned=True, returncode=result.returncode)
        if result.returncode:
            return dict(report, state='call-failed')
        try:
            return dict(report, **background_tasks(result.stdout, current_uid))
        except (ValueError, UnicodeError):
            return dict(report, state='unparseable')
    except Exception:
        return dict(report, state='call-unknown')


def main():
    if (sys.platform != 'darwin' or os.getuid() == 0
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.environ.get('GITHUB_REPOSITORY') != 'Apdelrahman1911/mobile-release-kit'
            or os.environ.get('GITHUB_REF') != 'refs/heads/verify/desktop-macos-candidate'):
        raise SystemExit('service diagnostic requires the disposable hosted candidate')
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location('_mrk_service_log_owner',
                                                 root / 'desktop/tools/macos_aqua_qualification.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    owner = module.load_owner(root)
    environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/Users/runner',
                   'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}
    report = collect(owner.run_owned, environment, root)
    # Do not start another diagnostic after an unknown original process return.
    if report['originalCallReturned']:
        report['backgroundTasks'] = collect_background_tasks(owner.run_owned, environment, root, os.getuid())
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
