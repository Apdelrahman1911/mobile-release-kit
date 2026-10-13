#!/usr/bin/env python3
"""Read one existing Apple submission log; never submit, sign or publish.

Apple: https://developer.apple.com/documentation/security/customizing-the-notarization-workflow
Only finite classifications/hashes leave memory. Successful diagnosis does not
change the original pipeline refusal or qualify an application for distribution.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import tempfile
import time

REPOSITORY = 'Apdelrahman1911/mobile-release-kit'
REF = 'refs/heads/verify/desktop-macos-notary-diagnostic'
WORKFLOW = '.github/workflows/desktop-macos-notary-diagnostic.yml'
CHECKOUT = Path('/Users/runner/work/mobile-release-kit/mobile-release-kit')
PARENT = Path('/Users/runner/work/_temp')
PUBLIC = 'mrk-notary-diagnostic-public.json'
SECRET = 'MRK_MACOS_NOTARY_API_KEY_BASE64'
# Frozen from the independently reviewed public receipt, not proved by Apple log metadata.
SOURCE = '42861e30546937d221890e7d25e6c633978347ce'
SOURCE_TREE = '8e79035c6b6e89c8c4d417cfd25f60a3fe921dba'
ORIGINAL_RECEIPT = '232c3ffeb7be9c1a085417227dc440f9741ca781ce8d42b958a7782911ffc4ad'
ORIGINAL_ARCHIVE = 'a62b6555342f70b907cc288eea5c782c11d12cc11de7b719fdf3c6f7acc88374'
SUBMISSION = '479ff35b-0731-4d22-8c5a-395aa8c409b4'
STATUS = 'Accepted'
ARCHIVE = 'MobileReleaseKit-notary-payload.zip'
ORIGINAL_LOG = '53737a949584ba02fa34fc7d2c6fb80f7628dc79b0afb617410c02413382ba01'
TEAM = '7CGZ2343AA'
CERTIFICATE = '5effa7d19bbe005b19c1617833cbe22186c2af96'
KEY_ID = '59VQCHM463'
ISSUER = '375572d7-6413-4f28-96af-2f39c49227fe'
XCODE = Path('/Applications/Xcode.app/Contents/Developer')
FIXED_TOOL = XCODE / 'usr/bin/notarytool'
READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
LIMIT = 1024 * 1024
PINS = {'desktop/tools/macos_android_helper_package.py': 'deb5ac1eeec7dadbfe0dde89eaf80f9d2baabd32c4477e2dc8c8b5a7b1617b1d', 'desktop/tools/macos_aqua_qualification.py': '0c6b5665cc74f21bc1fdf1c9f0d05a283d12a3dd1084d120cde96fc59fb1fe7b', 'desktop/packaging/macos-android-service-signing.profile': '7f1a96c30d75d915e84f1a45095170ba6e4b2870203efda199515c7260e98663', 'desktop/packaging/macos-notary-service.json': 'aef87ad93100be46f171523a830a5f6b67188c33748049aa843ea253c65e29b5'}
MESSAGES = {
    'The binary is not signed.': 'unsigned',
    'The signature of the binary is invalid.': 'invalid-signature',
    'The binary is not signed with a valid Developer ID certificate.': 'invalid-developer-id',
    'The executable does not have the hardened runtime enabled.': 'missing-hardened-runtime',
    'The signature does not include a secure timestamp.': 'missing-timestamp',
    'The executable requests the com.apple.security.get-task-allow entitlement.': 'get-task-allow',
    'The binary uses an SDK older than the 10.9 SDK.': 'unsupported-sdk',
    'Embedded entitlements are invalid: syntax error near line 1': 'malformed-entitlements',
    'The signature could not be validated because AMFI could not load its entitlements for validation: entitlements cannot be parsed': 'unparseable-entitlements',
}
# Exact topics from Apple's public guide, not message or defect classifications.
# Unknown URLs never leave memory and are not normalized into a recognized topic.
DOCUMENTATION_URLS = {
    'https://developer.apple.com/documentation/security/resolving-common-notarization-issues': 'common-notarization-guidance',
    'https://developer.apple.com/documentation/security/resolving-common-notarization-issues#Ensure-a-valid-code-signature': 'code-signature-guidance',
    'https://developer.apple.com/documentation/security/resolving-common-notarization-issues#Use-a-valid-Developer-ID-certificate': 'developer-id-guidance',
    'https://developer.apple.com/documentation/security/resolving-common-notarization-issues#Include-a-secure-timestamp': 'timestamp-guidance',
    'https://developer.apple.com/documentation/security/resolving-common-notarization-issues#Avoid-the-get-task-allow-entitlement': 'get-task-allow-guidance',
    'https://developer.apple.com/documentation/security/resolving-common-notarization-issues#Use-the-macOS-109-SDK-or-later': 'sdk-version-guidance',
    'https://developer.apple.com/documentation/security/resolving-common-notarization-issues#Enable-the-hardened-runtime': 'hardened-runtime-guidance',
    'https://developer.apple.com/documentation/security/resolving-common-notarization-issues#Handle-stapler-issues': 'stapler-guidance',
    'https://developer.apple.com/documentation/security/resolving-common-notarization-issues#Ensure-properly-formatted-entitlements': 'entitlements-guidance',
    'https://developer.apple.com/documentation/security/resolving-common-notarization-issues#Notarize-macOS-apps-with-external-dependencies': 'external-dependencies-guidance',
}
SUMMARIES = {
    'Archive contains critical validation errors': 'archive-validation-errors',
    'Team is not yet configured for notarization': 'team-not-configured',
    'Team is not yet configured for notarization.': 'team-not-configured',
}
PAYLOAD = 'Contents/Helpers/MobileReleaseKitPayload.app/Contents/'
PATHS = {
    'MobileReleaseKit.app/Contents/MacOS/mrk-macos-entry': 'outer-entry',
    'MobileReleaseKit.app/' + PAYLOAD + 'MacOS/mobile-release-kit-desktop': 'desktop-payload',
    'MobileReleaseKit.app/' + PAYLOAD + 'Frameworks/libmrk_desktop_image.dylib': 'desktop-image',
    'MobileReleaseKit.app/' + PAYLOAD + 'Frameworks/libmrk_resident_image.dylib': 'resident-image',
    'MobileReleaseKit.app/' + PAYLOAD + 'Helpers/mrk-vault-keychain': 'vault-helper',
    'MobileReleaseKit.app/' + PAYLOAD + 'Helpers/mrk-macos-remove': 'remover',
    'MobileReleaseKit.app/' + PAYLOAD + 'Helpers/mrk-github-seal': 'github-seal',
    'MobileReleaseKit.app/' + PAYLOAD + 'Helpers/mrk-android-register': 'android-helper',
    'runtime/python/bin/python3': 'runtime-python',
    'runtime/python/lib/python314.zip': 'runtime-python-zip-landmark',
    'runtime/tools/gh': 'runtime-github-provider',
}


class Refused(Exception):
    """Never publish exception text, native output or input paths."""


def need(condition):
    if not condition:
        raise Refused()


def sha(body):
    return hashlib.sha256(body).hexdigest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def classify_path(value):
    # Apple paths vary only in a known archive/container prefix. Unknown paths
    # never become command arguments, labels or public plaintext.
    for prefix in (ARCHIVE + '/payload-input/', 'payload-input/', ARCHIVE + '/'):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    return PATHS.get(value, 'unclassified')


# Exact current production notary_log_data literals, not arbitrary exception text.
STRICT_LOG_REFUSALS = frozenset((
    'notary-fixed-archive-name', 'notary-log-binding', 'notary-log-metadata',
    'notary-log-status-code', 'notary-log-upload-sha256', 'notary-log-issues-bound',
    'notary-log-issue-shape', 'notary-log-issue-metadata', 'notary-log-issue-code',
    'notary-log-tickets-bound', 'notary-log-ticket-shape', 'notary-log-success-with-errors',
))


def ticket_census(value, helper):
    """Separate closed DATA observations, never ticket or native-architecture authority."""
    result = {'kind': 'null' if value is None else 'list' if type(value) is list else 'other',
              'listCount': len(value) if type(value) is list else None,
              'state': 'observed', 'groupCount': 0, 'groups': [], 'omittedGroupCount': 0,
              'allGroupsSha256': sha(b'[]')}
    if value is None:
        return result
    if type(value) is not list or len(value) > 2048:
        result.update(state='over-bound' if type(value) is list else 'not-a-list',
                      groupCount=None, omittedGroupCount=None, allGroupsSha256=None)
        return result
    groups = {}
    for row in value:
        is_row = type(row) is dict
        row = row if is_row else {}
        raw_arch = row.get('arch')
        architecture = ('missing' if 'arch' not in row else 'null' if raw_arch is None else
                        raw_arch if type(raw_arch) is str and raw_arch in ('arm64', 'x86_64', 'i386', 'arm64e', 'x86_64h') else 'other')
        cdhash = row.get('cdhash')
        key = (architecture, is_row and set(row) == {'path', 'digestAlgorithm', 'cdhash', 'arch'},
               helper.notary_text(row.get('path'), 4096), row.get('digestAlgorithm') in ('SHA-1', 'SHA-256'),
               type(cdhash) is str and re.fullmatch(r'[0-9a-fA-F]{40}', cdhash) is not None,
               architecture in ('arm64', 'x86_64', 'i386'))  # Existing ZIP metadata syntax, never execution eligibility.
        groups[key] = groups.get(key, 0) + 1
    names = ('architecture', 'exactFourKeys', 'pathTextValid', 'digestAlgorithmAllowed',
             'cdhash40HexValid', 'strictArchitectureAllowed')
    rows = [dict(zip(names, key), count=count) for key, count in sorted(groups.items())]
    result.update(groupCount=len(rows), groups=rows[:64], omittedGroupCount=max(0, len(rows)-64),
                  allGroupsSha256=sha(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()))
    return result


def log_projection(body, helper):
    # No parser, census or issue projection may observe a different historical log.
    need(type(body) is bytes and len(body) <= LIMIT and sha(body) == ORIGINAL_LOG)
    value = helper.notary_json(body, LIMIT)
    need(type(value.get('logFormatVersion')) is int and value['logFormatVersion'] == 1
         and value.get('jobId') == SUBMISSION and value.get('status') == STATUS
         and value.get('archiveFilename') == ARCHIVE)
    current_sha = value.get('sha256')
    need(type(current_sha) is str and current_sha == ORIGINAL_ARCHIVE)
    checked, refusal = None, None
    try:
        checked = helper.notary_log_data(body, {'id': SUBMISSION, 'status': STATUS}, ORIGINAL_ARCHIVE,
                                         archive_name=ARCHIVE)
    except helper.Refused as error:
        literal = str(error)
        refusal = literal if literal in STRICT_LOG_REFUSALS else 'unclassified'
    # The strict original result is immutable; the census cannot upgrade it.
    census = ticket_census(value.get('ticketContents'), helper)
    if 'ticketContents' not in value:
        census.update(kind='missing', state='not-supplied', groupCount=None,
                      omittedGroupCount=None, allGroupsSha256=None)
    groups = {}
    if checked is not None:
        for row in value['issues'] or ():
            architecture = row.get('architecture')
            architecture = architecture if architecture in ('arm64', 'x86_64') else ('not-supplied' if architecture is None else 'other')
            doc_url = row.get('docUrl')
            documentation = 'not-supplied' if doc_url is None else DOCUMENTATION_URLS.get(doc_url, 'unclassified')
            key = (row['severity'], row.get('code'), architecture, classify_path(row['path']),
                   MESSAGES.get(row['message'], 'unclassified'), documentation, sha(row['path'].encode()), sha(row['message'].encode()))
            groups[key] = groups.get(key, 0) + 1
    rows = [dict(zip(('severity', 'code', 'architecture', 'pathRole', 'messageClass', 'documentationClass', 'pathSha256', 'messageSha256'), key), count=count)
            for key, count in sorted(groups.items(), key=lambda item: repr(item[0]))]
    summary = value.get('statusSummary')
    summary_valid = helper.notary_text(summary, 4096)
    code = value.get('statusCode')
    return {'currentObservedStatus': STATUS, 'logSha256': sha(body), 'historicalBytesMatch': sha(body) == ORIGINAL_LOG,
            'strictLogAccepted': checked is not None, 'strictLogRefusal': refusal,
            'ticketCensus': census, 'payloadNotarizationQualified': False, 'productReady': False,
            'statusCode': code if type(code) is int and 0 <= code <= 999999 else None,
            'statusSummaryClass': SUMMARIES.get(summary, 'unclassified') if summary_valid else 'not-supplied' if summary is None else 'unclassified',
            'statusSummarySha256': sha(summary.encode()) if summary_valid else None,
            # Compared to the receipt's pin; this read-only job does not reopen the archive.
            'archiveShaIndependentlyCompared': True,
            'errorCount': checked['errorCount'] if checked is not None else None,
            'warningCount': checked['warningCount'] if checked is not None else None,
            'ticketRowCount': checked['ticketRowCount'] if checked is not None else None,
            'issueProjectionState': 'observed' if checked is not None else 'unavailable-strict-log-refused',
            'issueGroupCount': len(rows) if checked is not None else None, 'issueGroups': rows[:64],
            'omittedGroupCount': max(0, len(rows) - 64) if checked is not None else None,
            'allIssueGroupsSha256': sha(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()) if checked is not None else None}


class Clock:
    def __init__(self, now=time.monotonic):
        self.now = now
        self.start = self.last = now()

    def check(self, cleanup=False):
        value = self.now()
        need(type(value) in (int, float) and self.last <= value < self.start + (300 if cleanup else 240))
        self.last = value
        return value

    def timeout(self):
        value = self.check()
        result = min(180, int(self.start + 240 - value - 5))
        need(result >= 1)
        return result


class Tool:
    """The fixed Xcode original; same ancestry policy as notary_tool()."""
    def __init__(self):
        self.fd = None
        self.path = FIXED_TOOL.resolve(strict=True)
        applications = XCODE.parents[2]
        need(self.path.is_absolute() and len(self.path.parts) <= 16 and applications.resolve(strict=True) in self.path.parents)
        self.originals = []
        for path in sorted({FIXED_TOOL, self.path, *FIXED_TOOL.parents, *self.path.parents}, key=lambda p: (len(p.parts), str(p))):
            info = path.lstat()
            alias = stat.S_ISLNK(info.st_mode) and path == XCODE.parent.parent
            trusted_group = path == applications and stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid in (0, 80) and not info.st_mode & 0o002
            need(info.st_uid in (0, os.getuid()) and (alias or (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                 and (path in applications.parents or not info.st_mode & 0o022 or trusted_group)))
            self.originals.append((path, identity(info), os.readlink(path) if alias else None))
        fd = os.open(self.path, READ)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 64 * LIMIT and info.st_mode & 0o111
                 and not info.st_mode & 0o022 and info.st_uid in (0, os.getuid()) and identity(info) == identity(self.path.lstat()))
            self.original = identity(info)
            self.fd = fd
            self.post()
        except BaseException:
            self.fd = None
            os.close(fd)
            raise

    def post(self):
        for path, original, link in self.originals:
            need(identity(path.lstat()) == original and (link is None or os.readlink(path) == link))
        need(FIXED_TOOL.resolve(strict=True) == self.path and identity(os.fstat(self.fd)) == self.original == identity(self.path.lstat()))

    def close(self):
        fd, self.fd = self.fd, None
        if fd is not None:
            os.close(fd)  # Consumed once; never retry an uncertain close.


_DARWIN_XATTRS = None


def no_xattrs(fd):
    # Same fixed read-only FD ABI as stage_macos_installed.no_xattrs. CPython's
    # os.listxattr belongs to its Linux-only extended-attribute API.
    global _DARWIN_XATTRS
    if sys.platform == 'darwin':
        if _DARWIN_XATTRS is None:
            import ctypes
            library = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
            call = library.flistxattr
            call.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            call.restype = ctypes.c_ssize_t
            _DARWIN_XATTRS = call
        need(_DARWIN_XATTRS(fd, None, 0, 0) == 0)
    elif sys.platform == 'linux':
        need(not os.listxattr(fd))
    else:
        raise Refused()


class KeyDirectory:
    """Small task-owned key scope, never recursive or shared cleanup."""
    def __init__(self, parent):
        self.parent = parent
        self.parent_fd = self.root_fd = self.key_fd = None
        self.path = None
        self.key_original = self.body = None
        self.created = self.closed = self.retired = self.scratch_retired = False
        try:
            self._open(parent)
        except BaseException:
            # Partial setup has no child/native original. Consume each opened
            # FD once; retain any nonempty/unestablished task directory.
            for attr in ('key_fd', 'root_fd', 'parent_fd'):
                fd = getattr(self, attr)
                setattr(self, attr, None)
                if fd is not None:
                    try:
                        os.close(fd)
                    except BaseException:
                        pass
            raise Refused() from None

    def _open(self, parent):
        self.parent_fd = os.open(parent, READ | os.O_DIRECTORY)
        self.parent_original = directory(os.fstat(self.parent_fd))
        need(self.parent_original == directory(parent.lstat()))
        self.path = Path(tempfile.mkdtemp(prefix='mrk-notary-log-', dir=parent))
        self.root_fd = os.open(self.path, READ | os.O_DIRECTORY)
        self.root_original = directory(os.fstat(self.root_fd))
        need(self.root_original == directory(self.path.lstat()) and stat.S_IMODE(os.fstat(self.root_fd).st_mode) == 0o700
             and os.fstat(self.root_fd).st_uid == os.getuid())
        for name in ('home', 'tmp'):
            os.mkdir(name, 0o700, dir_fd=self.root_fd)
        self.child_originals = {name: directory(os.stat(name, dir_fd=self.root_fd, follow_symlinks=False)) for name in ('home', 'tmp')}
        self.key_name = 'AuthKey_' + KEY_ID + '.p8'

    def create_key(self, body):
        need(self.key_fd is None and not self.created and type(body) is bytes and 0 < len(body) <= 8192)
        self.post()
        self.key_fd = os.open(self.key_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.root_fd)
        self.created = True
        offset = 0
        while offset < len(body):
            count = os.write(self.key_fd, body[offset:])
            need(count > 0)
            offset += count
        os.fsync(self.key_fd)
        os.fchmod(self.key_fd, 0o400)
        self.body = body
        self.key_original = identity(os.fstat(self.key_fd))
        self.post()

    def post(self):
        need(directory(os.fstat(self.parent_fd)) == self.parent_original == directory(self.parent.lstat())
             and directory(os.fstat(self.root_fd)) == self.root_original
             == directory(os.stat(self.path.name, dir_fd=self.parent_fd, follow_symlinks=False)))
        need(set(os.listdir(self.root_fd)) == ({'home', 'tmp', self.key_name} if self.created else {'home', 'tmp'}))
        for name, original in self.child_originals.items():
            need(directory(os.stat(name, dir_fd=self.root_fd, follow_symlinks=False)) == original)
        if self.created:
            need(self.key_original is not None and identity(os.fstat(self.key_fd)) == self.key_original
                 == identity(os.stat(self.key_name, dir_fd=self.root_fd, follow_symlinks=False))
                 and stat.S_ISREG(os.fstat(self.key_fd).st_mode) and os.fstat(self.key_fd).st_nlink == 1
                 and os.pread(self.key_fd, 8193, 0) == self.body)
            no_xattrs(self.key_fd)

    def finish(self, known):
        error = None
        try:
            self.post()
            if self.key_fd is not None:
                fd, self.key_fd = self.key_fd, None
                os.close(fd)
                self.closed = True
            if known and self.created:
                need(identity(os.stat(self.key_name, dir_fd=self.root_fd, follow_symlinks=False)) == self.key_original)
                os.unlink(self.key_name, dir_fd=self.root_fd)
                need(self.key_name not in os.listdir(self.root_fd))
                self.retired = True
            if known and (not self.created or self.retired):
                # Only exact admitted empty children may retire. Native-created
                # contents are retained, never recursively deleted or hidden.
                empty = True
                for name, original in self.child_originals.items():
                    fd = os.open(name, READ | os.O_DIRECTORY, dir_fd=self.root_fd)
                    try:
                        need(directory(os.fstat(fd)) == original)
                        empty = empty and not os.listdir(fd)
                    finally:
                        os.close(fd)
                if empty:
                    for name, original in self.child_originals.items():
                        need(directory(os.stat(name, dir_fd=self.root_fd, follow_symlinks=False)) == original)
                        os.rmdir(name, dir_fd=self.root_fd)
                    need(not os.listdir(self.root_fd))
                    fd, self.root_fd = self.root_fd, None
                    os.close(fd)
                    need(directory(os.stat(self.path.name, dir_fd=self.parent_fd, follow_symlinks=False)) == self.root_original)
                    os.rmdir(self.path.name, dir_fd=self.parent_fd)
                    self.scratch_retired = True
        except BaseException as caught:
            error = caught
        finally:
            for attr in ('key_fd', 'root_fd', 'parent_fd'):
                fd = getattr(self, attr)
                setattr(self, attr, None)
                if fd is not None:
                    try:
                        os.close(fd)
                        if attr == 'key_fd':
                            self.closed = True
                    except BaseException as caught:
                        error = error or caught
        if error is not None:
            raise Refused() from None


def query(owner, helper, key, profile, tool, clock):
    report = {'historicalSubmission': {'source': SOURCE, 'sourceTree': SOURCE_TREE, 'publicReceiptSha256': ORIGINAL_RECEIPT,
        'archiveFilename': ARCHIVE, 'archiveSha256': ORIGINAL_ARCHIVE, 'logSha256': ORIGINAL_LOG,
        'runId': '38332288631', 'attempt': '1',
        'jobId': '115084521846', 'target': 'aarch64-apple-darwin', 'id': SUBMISSION, 'status': STATUS},
        'currentObservedStatus': None, 'diagnosticPassed': False, 'qualification': 'read-only-existing-submission-diagnostic',
        'failureStage': None, 'cleanupErrors': [], 'entered': False, 'returned': False,
        'knownExit': False, 'returncode': None, 'toolClosed': False}
    stage = 'pre-call'
    known = True  # No entered original yet; pre-call refusal may retire own key.
    try:
        clock.check(); key.post(); tool.post()
        environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(key.path / 'home'),
                       'TMPDIR': str(key.path / 'tmp'), 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'DEVELOPER_DIR': str(XCODE)}
        argv = [str(tool.path), 'log', SUBMISSION, '--key', str(key.path / key.key_name),
                '--key-id', profile['keyId'], '--issuer', profile['issuerId']]
        timeout = clock.timeout()
        stage = 'original-log-call'
        report['entered'] = True  # API entered, not a fabricated child-start claim.
        known = False  # Latch before the one original API invocation.
        result = owner.run_owned(argv, environ=environment, cwd=key.path, timeout=timeout,
                                 capture=True, text=False, output_limit=LIMIT)
        report['returned'] = True
        known = (type(result.returncode) is int and 0 <= result.returncode <= 255
                 and type(result.stdout) is bytes and type(result.stderr) is bytes
                 and len(result.stdout) + len(result.stderr) <= LIMIT)
        report['knownExit'] = known
        if known:
            report['returncode'] = result.returncode
        need(known)
        stage = 'original-post'
        clock.check(); key.post(); tool.post()
        need(result.returncode == 0 and not result.stderr)
        stage = 'log-validation'
        report.update(log_projection(result.stdout, helper))
    except BaseException:
        report['failureStage'] = stage
    finally:
        for label, finish in (('credential-retirement', lambda: key.finish(known)), ('tool-close', tool.close),
                              ('final-deadline', lambda: clock.check(cleanup=True))):
            try:
                finish()
                if label == 'tool-close':
                    report['toolClosed'] = True
            except BaseException:
                report['cleanupErrors'].append(label)
                if report['failureStage'] is None:
                    report['failureStage'] = label
        report['authentication'] = {'created': key.created, 'closed': key.closed, 'retired': key.retired}
        report['scratchRetired'] = key.scratch_retired
        report['diagnosticPassed'] = (report['failureStage'] is None and known and key.retired and key.closed
                                      and report['toolClosed'] and report['currentObservedStatus'] == STATUS)
    return report


def source_read(root, relative):
    path = root / relative
    fd = os.open(path, READ)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= LIMIT)
        body = os.pread(fd, LIMIT + 1, 0)
        need(len(body) == info.st_size and identity(os.fstat(fd)) == identity(info) == identity(path.lstat())
             and sha(body) == PINS[relative])
        return body
    finally:
        os.close(fd)


def load_module(root, relative, name):
    body = source_read(root, relative)
    spec = importlib.util.spec_from_file_location(name, root / relative)
    need(spec is not None and spec.loader is not None)
    need(name not in sys.modules)
    module = importlib.util.module_from_spec(spec)
    # Standard importlib registration is required by future-annotation
    # dataclasses in the existing passive owner-loader module.
    sys.modules[name] = module
    try:
        exec(compile(body, str(root / relative), 'exec'), module.__dict__)
        need(sys.modules.get(name) is module)
        source_read(root, relative)
        return module
    except BaseException:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise


def admit(environment):
    source = environment.get('GITHUB_SHA', '')
    need(platform.system() == 'Darwin' and platform.machine() == 'arm64' and os.getuid() != 0
         and re.fullmatch('[0-9a-f]{40}', source) and environment.get('GITHUB_WORKFLOW_SHA') == source)
    required = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'macOS',
                'RUNNER_ARCH': 'ARM64', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_REPOSITORY': REPOSITORY,
                'GITHUB_REF': REF, 'GITHUB_WORKSPACE': str(CHECKOUT), 'RUNNER_TEMP': str(PARENT),
                'GITHUB_WORKFLOW_REF': REPOSITORY + '/' + WORKFLOW + '@' + REF}
    need(all(environment.get(k) == v for k, v in required.items()))
    need(Path(__file__).absolute() == CHECKOUT / 'desktop/tools/macos_notary_diagnostic.py'
         and (CHECKOUT / '.git/HEAD').read_bytes() == source.encode() + b'\n')
    for name in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        need(re.fullmatch('[1-9][0-9]{0,19}', environment.get(name, '')))
    return {'source': source, 'runId': environment['GITHUB_RUN_ID'], 'attempt': environment['GITHUB_RUN_ATTEMPT'],
            'target': 'aarch64-apple-darwin'}


def publish(parent, report):
    body = (json.dumps(report, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    need(len(body) <= 65536)
    parent_fd = os.open(parent, READ | os.O_DIRECTORY)
    fd = None
    try:
        original_parent = directory(os.fstat(parent_fd))
        need(original_parent == directory(parent.lstat()))
        fd = os.open(PUBLIC, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
        offset = 0
        while offset < len(body):
            written = os.write(fd, body[offset:]); need(written > 0); offset += written
        os.fsync(fd)
        original = identity(os.fstat(fd))
        need(os.pread(fd, 65537, 0) == body and original == identity(os.stat(PUBLIC, dir_fd=parent_fd, follow_symlinks=False)))
        consumed, fd = fd, None
        os.close(consumed)
        need(original == identity(os.stat(PUBLIC, dir_fd=parent_fd, follow_symlinks=False))
             and original_parent == directory(os.fstat(parent_fd)) == directory(parent.lstat()))
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)


def main():
    environment = dict(os.environ)
    secret = environment.pop(SECRET, None)
    os.environ.clear()  # No inherited credentials/configuration reach imports or children.
    report = {'diagnosticPassed': False, 'failureStage': 'admission', 'currentObservedStatus': None}
    key = tool = None
    clock = Clock()
    handed_off = False
    try:
        context = admit(environment)
        report['diagnosticWorkflow'] = context
        report['failureStage'] = 'dependencies'
        helper = load_module(CHECKOUT, 'desktop/tools/macos_android_helper_package.py', 'mrk_notary_diagnostic_helper')
        qualification = load_module(CHECKOUT, 'desktop/tools/macos_aqua_qualification.py', 'mrk_notary_diagnostic_owner_loader')
        source_read(CHECKOUT, 'desktop/packaging/macos-android-service-signing.profile')
        profile = helper.notary_service(source_read(CHECKOUT, 'desktop/packaging/macos-notary-service.json'), (TEAM, CERTIFICATE))
        need(profile['keyId'] == KEY_ID and profile['issuerId'] == ISSUER)
        owner = qualification.load_owner(CHECKOUT)
        clock.check()
        report['failureStage'] = 'authentication'
        body = helper.notary_key_data({SECRET: secret})
        secret = None
        key = KeyDirectory(PARENT)
        key.create_key(body)
        body = None
        report['failureStage'] = 'tool-admission'
        tool = Tool()
        handed_off = True
        report = query(owner, helper, key, profile, tool, clock)
        report['diagnosticWorkflow'] = context
        for relative in PINS:
            source_read(CHECKOUT, relative)
        clock.check(cleanup=True)
    except BaseException:
        report['diagnosticPassed'] = False
        if report.get('failureStage') is None:
            report['failureStage'] = 'source-finality'
    finally:
        if not handed_off:
            for value, action in ((key, lambda: key.finish(True)), (tool, lambda: tool.close())):
                if value is not None:
                    try:
                        action()
                    except BaseException:
                        report['setupCleanupUnknown'] = True
        try:
            # No output on a different host/route. Publication itself is fixed,
            # exclusive, bounded and cannot expose private native transcripts.
            if 'diagnosticWorkflow' in report:
                publish(PARENT, report)
        except BaseException:
            return 1
    return 0 if report['diagnosticPassed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
