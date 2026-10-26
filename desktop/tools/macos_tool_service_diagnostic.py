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
    print(json.dumps(collect(owner.run_owned, environment, root), sort_keys=True))


if __name__ == '__main__':
    main()
