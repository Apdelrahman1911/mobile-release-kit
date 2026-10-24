#!/usr/bin/env python3
"""Read-only diagnosis of one failed MRK notarization interval, never submission.

Uses Apple's documented `notarytool history` / `log` commands:
https://developer.apple.com/documentation/security/customizing-the-notarization-workflow
History correlation is NOT a source or artifact provenance claim.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import resource
import stat
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))
from desktop.tools.macos_android_helper_package import notary_json, notary_key_data, notary_service, notary_uuid, notary_issue_summary
from mobile_release.owned_process import ProcessError, run_owned

BRANCH = 'verify/desktop-macos-notary-inspect'
ARCHIVE = 'MobileReleaseKit-notary-payload.zip'
# Actual failed payload-submit step in run40071418028/1, ARM Git job120805474247.
START = '2026-10-24T07:53:36Z'
END = '2026-10-24T08:01:05Z'



def need(value):
    if not value:
        raise ValueError('notary-inspection-refused')


def instant(value):
    need(type(value) is str and len(value) <= 40
         and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})', value))
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    need(parsed.utcoffset() is not None)
    return parsed.astimezone(timezone.utc)


def select_submission(body, start=START, end=END):
    value = notary_json(body, 2 << 20)
    need(set(value) <= {'history', 'message'} and type(value.get('history')) is list
         and 0 < len(value['history']) <= 512)
    lower, upper = instant(start), instant(end)
    need(lower < upper)
    candidates, observed, ids = [], [], set()
    for row in value['history']:
        need(type(row) is dict)
        created = instant(row.get('createdDate')); observed.append(created)
        identity = notary_uuid(row.get('id'))
        need(identity not in ids); ids.add(identity)
        if lower <= created <= upper and row.get('name') == ARCHIVE:
            need(row.get('status') in ('Accepted', 'Invalid', 'In Progress'))
            candidates.append({'id': identity, 'status': row['status']})
    # A truncated history that stops inside the interval cannot establish unique
    # correlation. Never choose the newest/first row or expose other submissions.
    if min(observed) > lower:
        return None, 'history-coverage-unavailable'
    if len(candidates) != 1:
        return None, 'no-match' if not candidates else 'ambiguous'
    if candidates[0]['status'] == 'In Progress':
        return None, 'not-terminal'
    return candidates[0], 'unique-interval-correlation'


def log_projection(body, submission, start=START, end=END):
    value = notary_json(body, 1 << 20)
    need(notary_uuid(value.get('jobId')) == submission['id'] and value.get('status') == submission['status']
         and value.get('archiveFilename') == ARCHIVE and instant(start) <= instant(value.get('uploadDate')) <= instant(end))
    code = value.get('statusCode')
    need(code is None or type(code) is int and 0 <= code <= 999999)
    issues = value.get('issues')
    need(issues is None or type(issues) is list and len(issues) <= 2048)
    return {'status': submission['status'], 'statusCode': code, 'issueCount': len(issues or []),
            'issues': notary_issue_summary(issues)}


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def inspect(work, key, profile, *, command=run_owned, clock=time.monotonic, diagnostic=None):
    """One private key original; uncertain children/close never authorize unlink."""
    diagnostic = {} if diagnostic is None else diagnostic
    diagnostic.update(stage='key-prepare', cleanup='not-entered')
    endpoint = clock() + 150
    parent = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    parent_id = None
    fd = None; original = None; settled = True; ready = False
    def post():
        need(identity(os.fstat(parent))[:5] == identity(os.stat(work, follow_symlinks=False))[:5] == parent_id)
        need(identity(os.fstat(fd)) == identity(os.stat('key.p8', dir_fd=parent, follow_symlinks=False)) == original)
        need(os.pread(fd, len(key) + 1, 0) == key)
    def call(verb, *args):
        nonlocal settled
        post(); remaining = int(endpoint - clock()) - 10; need(remaining > 0)
        argv = ['/usr/bin/xcrun', 'notarytool', verb, *args, '--key', str(work / 'key.p8'),
                '--key-id', profile['keyId'], '--issuer', profile['issuerId']]
        if verb == 'history': argv += ['--output-format', 'json']
        env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(work), 'TMPDIR': str(work) + '/',
               'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'DEVELOPER_DIR': '/Applications/Xcode.app/Contents/Developer'}
        diagnostic['stage'] = verb
        settled = False
        try:
            result = command(argv, environ=env, cwd=work, timeout=min(60, remaining),
                             text=False, capture=True, output_limit=2 << 20)
            settled = True
        except ProcessError as error:
            settled = error.contained is True and error.cleanup_complete is True
            raise
        post(); need(clock() < endpoint and result.returncode == 0)
        return result.stdout
    try:
        info = os.fstat(parent); parent_id = identity(info)[:5]
        need(stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid() != 0
             and info.st_gid == os.getgid() and os.listdir(parent) == [])
        fd = os.open('key.p8', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        original = identity(os.fstat(fd))
        need(stat.S_ISREG(original[2]) and original[5:7] == (1, 0))
        at = 0
        while at < len(key):
            written = os.write(fd, key[at:]); need(written > 0); at += written
        os.fchmod(fd, 0o400); os.fsync(fd); original = identity(os.fstat(fd)); post(); ready = True
        body = call('history'); diagnostic['stage'] = 'history-selection'
        submission, selection = select_submission(body)
        result = {'correlation': selection, 'notary': None}
        if submission is not None:
            body = call('log', submission['id']); diagnostic['stage'] = 'log-projection'
            result['notary'] = log_projection(body, submission)
        return result
    finally:
        # Close each original descriptor once, even if the postcondition fails.
        # An uncertain producer/close or incomplete write never licenses deletion.
        diagnostic['cleanup'] = 'directory-retained' if fd is None else 'key-retained'
        errors = []
        removable = False
        if fd is not None:
            if settled and ready:
                try:
                    post(); removable = True
                except BaseException as error:
                    errors.append(error)
            consumed, fd = fd, None
            try:
                os.close(consumed)
            except BaseException as error:
                removable = False; errors.append(error)
            if removable:
                try:
                    need(identity(os.stat(work, follow_symlinks=False))[:5] == parent_id)
                    need(identity(os.stat('key.p8', dir_fd=parent, follow_symlinks=False)) == original)
                    os.unlink('key.p8', dir_fd=parent)
                    diagnostic['cleanup'] = 'key-removed-directory-retained'
                    need(os.listdir(parent) == [])
                    need(identity(os.stat(work, follow_symlinks=False))[:5] == parent_id)
                    os.rmdir(work)
                    diagnostic['cleanup'] = 'complete'
                except BaseException as error:
                    errors.append(error)
        try:
            os.close(parent)
        except BaseException as error:
            errors.append(error)
        if errors:
            if diagnostic['cleanup'] == 'complete': diagnostic['cleanup'] = 'close-uncertain'
            # The primary failure remains __context__; no exception text or
            # traceback is ever exported by main, including cleanup failures.
            raise BaseExceptionGroup('notary-inspection-cleanup-incomplete', errors)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    encoded = os.environ.pop('MRK_MACOS_NOTARY_API_KEY_BASE64', None)
    diagnostic = {'stage': 'environment', 'cleanup': 'not-entered'}
    try:
        need(sys.platform == 'darwin' and os.getuid() == os.geteuid() != 0 and len(sys.argv) == 1
             and os.environ.get('GITHUB_REPOSITORY') == 'Apdelrahman1911/mobile-release-kit'
             and os.environ.get('GITHUB_EVENT_NAME') == 'push'
             and os.environ.get('GITHUB_REF') == 'refs/heads/' + BRANCH
             and os.environ.get('GITHUB_SHA') == os.environ.get('GITHUB_WORKFLOW_SHA')
             and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
             and os.environ.get('RUNNER_TEMP') == '/Users/runner/work/_temp')
        diagnostic['stage'] = 'credential'
        key = notary_key_data({'MRK_MACOS_NOTARY_API_KEY_BASE64': encoded}); encoded = None
        diagnostic['stage'] = 'profile'
        with (ROOT / 'desktop/packaging/macos-notary-service.json').open('rb') as source:
            profile = notary_service(source.read(1025), ('7CGZ2343AA', None))
        diagnostic['stage'] = 'private-directory'
        work = Path(tempfile.mkdtemp(prefix='mrk-notary-inspect-', dir=os.environ['RUNNER_TEMP']))
        result = inspect(work, key, profile, diagnostic=diagnostic)
        result.update(diagnosticOnly=True, sourceAuthenticated=False, productReady=False, cleanupComplete=True,
                      producerRun=40071418028, producerAttempt=1, producerJob=120805474247)
        print(json.dumps(result, separators=(',', ':')))
        return 0 if result['notary'] is not None else 1
    except BaseException:
        print(json.dumps(dict(diagnostic, inspection='unavailable', rawOutputExported=False, productReady=False),
                         separators=(',', ':')), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
