#!/usr/bin/env python3
"""Validate one Android UI result against the original installed-package facts.

This is a non-publishing, non-native result reader. Code comes from the exact
Actions checkout; package/profile DATA retains its inventory and digest checks.
Importing this module does not read inputs, load adapters, or publish a result.
"""
from __future__ import annotations

import time
# Include remaining imports in the original one-minute CLI budget.
_STARTED_NS = time.monotonic_ns() if __name__ == "__main__" else None

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

SOURCE = Path('/Users/runner/work/mobile-release-kit/mobile-release-kit')

def need(condition, reason):
    if not condition: raise ValueError(reason)

def nine(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def unique(rows):
    need(len(rows) <= 4096 and len({key for key, _ in rows}) == len(rows), 'ui-duplicate-fields')
    return dict(rows)

def document(body):
    def nonfinite(_): raise ValueError('ui-json-number')
    def finite(value):
        number = float(value)
        need(number != float('inf') and number != -float('inf'), 'ui-json-number')
        return number
    value = json.loads(body, object_pairs_hook=unique, parse_constant=nonfinite, parse_float=finite)
    need(type(value) is dict, 'ui-json-object')
    return value

def sha(body):
    return hashlib.sha256(body).hexdigest()

def package_originals(rows, roles, *, credentials=False):
    need(type(rows) is list and len(rows) == len(roles), 'ui-original-count')
    for row, role in zip(rows, roles, strict=True):
        flags = ('entered', 'returned', 'settled') if credentials else ('entered', 'returned', 'capturesSettled')
        key = 'status' if credentials else 'returncode'
        allowed = (0, 1) if not credentials and role in ('installer-log-cursor', 'installer-log-capture') else (0,)
        need(type(row) is dict and row.get('role') == role and all(row.get(flag) is True for flag in flags)
             and type(row.get(key)) is int and row[key] in allowed, 'ui-original-result')


def load_checkout_modules(clock):
    """Ordinary imports of fixed trusted checkout code, not artifact admission."""
    modules = []
    for name, relative in (('mrk_android_ui_normal', 'desktop/tools/macos_normal_ui_runner.py'),
                           ('mrk_android_ui_stager', 'desktop/tools/stage_macos_installed.py'),
                           ('mrk_android_ui_package', 'desktop/tools/macos_android_helper_package.py')):
        clock()
        need(name not in sys.modules, 'ui-source-module-collision')
        spec = importlib.util.spec_from_file_location(name, SOURCE / relative)
        need(spec is not None and spec.loader is not None, 'ui-source-module-unavailable')
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            del sys.modules[name]
            raise
        clock()
        modules.append(module)
    return tuple(modules)


def main():
    env = dict(os.environ)
    TARGET = env['MRK_MACOS_TARGET']
    if TARGET not in ('aarch64-apple-darwin', 'x86_64-apple-darwin'): raise ValueError('ui-fixed-target')
    root = Path(env['MRK_MACOS_WORK'])
    normal = root / 'normal-ui'
    source = env['GITHUB_SHA']
    run, attempt = env['GITHUB_RUN_ID'], env['GITHUB_RUN_ATTEMPT']
    last = _STARTED_NS if _STARTED_NS is not None else time.monotonic_ns()
    deadline = last + 60 * 10**9
    held, directories, originals = [], {}, {}
    primary = None


    def clock():
        nonlocal last
        now = time.monotonic_ns()
        need(last <= now < deadline, 'ui-data-deadline')
        last = now





    def directory(path):
        clock()
        if path in directories: return directories[path]
        need(path.is_absolute() and len(path.parts) <= 24 and '..' not in path.parts, 'ui-fixed-path')
        parent = directory(path.parent) if path != Path('/') else None
        fd = os.open(path.name if parent else '/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=None if parent is None else parent['fd'])
        row = dict(fd=fd, parent=parent, name=path.name if parent else '/', before=None, body=None)
        held.append(row)  # Adopt before fstat.
        before = nine(os.fstat(fd))
        need(stat.S_ISDIR(before[2]) and before[3] in (0, os.getuid()) and not before[2] & 0o022,
             'ui-directory-policy')
        row['before'] = before[:5]
        need(nine(os.stat(row['name'], dir_fd=None if parent is None else parent['fd'],
                          follow_symlinks=False))[:5] == row['before'], 'ui-directory-original')
        directories[path] = row
        return row

    def original(path, limit):
        clock()
        need(type(limit) is int and 0 < limit <= 2 << 20, 'ui-read-limit')
        if path in originals:
            row = originals[path]
            need(len(row['body']) <= limit, 'ui-original-limit')
            return row['body']
        parent = directory(path.parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent['fd'])
        row = dict(fd=fd, parent=parent, name=path.name, before=None, body=None)
        held.append(row)
        before = nine(os.fstat(fd))
        need(stat.S_ISREG(before[2]) and before[3:5] == (os.getuid(), os.getgid()) and before[5] == 1
             and not before[2] & 0o022 and 0 < before[6] <= limit, 'ui-file-policy')
        need(nine(os.stat(path.name, dir_fd=parent['fd'], follow_symlinks=False)) == before, 'ui-file-pre')
        chunks = []
        for offset in range(0, before[6], 65536):
            clock()
            part = os.pread(fd, min(65536, before[6] - offset), offset)
            need(len(part) == min(65536, before[6] - offset), 'ui-original-short')
            chunks.append(part)
        need(not os.pread(fd, 1, before[6]) and nine(os.fstat(fd)) == before
             == nine(os.stat(path.name, dir_fd=parent['fd'], follow_symlinks=False)), 'ui-original-post')
        row.update(before=before, body=b''.join(chunks))
        originals[path] = row
        return row['body']

    def original_post():
        for row in held:
            clock()
            parent_fd = None if row['parent'] is None else row['parent']['fd']
            current, named = nine(os.fstat(row['fd'])), nine(os.stat(row['name'], dir_fd=parent_fd, follow_symlinks=False))
            if row['body'] is None:
                need(current[:5] == named[:5] == row['before'], 'ui-parent-post')
            else:
                need(current == named == row['before'], 'ui-file-post')
                body = row['body']
                for offset in range(0, len(body), 65536):
                    clock()
                    need(os.pread(row['fd'], min(65536, len(body) - offset), offset) == body[offset:offset + 65536],
                         'ui-bytes-post')
                need(not os.pread(row['fd'], 1, len(body)) and nine(os.fstat(row['fd'])) == row['before']
                     == nine(os.stat(row['name'], dir_fd=parent_fd, follow_symlinks=False)), 'ui-eof-post')


    try:
        clock()
        need(re.fullmatch('/Users/runner/work/_temp/mrk-macos-installed[.][A-Za-z0-9]{8}', str(root))
             and os.getuid() != 0 and Path.cwd() == SOURCE and env['GITHUB_WORKSPACE'] == str(SOURCE)
             and env['GITHUB_REPOSITORY'] == 'Apdelrahman1911/mobile-release-kit'
             and env['GITHUB_EVENT_NAME'] == 'push'
             and env['GITHUB_REF'] == 'refs/heads/verify/desktop-macos-installed'
             and env['GITHUB_WORKFLOW_REF'] == 'Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-installed.yml@refs/heads/verify/desktop-macos-installed'
             and re.fullmatch('[0-9a-f]{40}', source) and source == env['GITHUB_WORKFLOW_SHA'] == env['MRK_EXPECTED_SHA']
             and all(re.fullmatch('[1-9][0-9]{0,19}', value) for value in (run, attempt))
             and env['MRK_MACOS_TARGET'] == TARGET
             and env['MRK_MACOS_ANDROID_UI_SCOPE'] == 'android-signed-build', 'ui-current-context')
        for path in (root, normal):
            item = directory(path)
            need(item['before'][3:5] == (os.getuid(), os.getgid()) and stat.S_IMODE(item['before'][2]) == 0o700,
                 'ui-private-parent')
        for name in ('normal-build.status', 'package-finalization.status', 'package-install.status', 'installer-output.status',
                     'normal-ui/build.status', 'normal-ui/android-inputs.status',
                     'normal-ui/android-signed-build-test.status', 'normal-ui/android-signed-build-summary.status'):
            need(original(root / name, 4) == b'0\n', 'ui-actual-original-status')
        binding = document(original(root / 'source-binding.json', 65536))
        inventory = document(original(root / 'source-inventory.json', 2 << 20))
        need(binding.get('source') == binding.get('workflowSource') == inventory.get('source') == source
             and binding.get('runId') == run and binding.get('runAttempt') == attempt
             and binding.get('target') == TARGET and binding.get('packageRole') == 'ordinary-image'
             and binding.get('scope') == 'engineering-acl-probe-five-regressions-fixed-fixture-package-install-only'
             and binding.get('workDirectory') == [directory(root)['before'][0], directory(root)['before'][1], os.getuid()]
             and type(binding.get('tree')) is str and re.fullmatch('[0-9a-f]{40}', binding['tree'])
             and binding['tree'] == inventory.get('tree'), 'ui-source-binding')
        rows = inventory.get('files')
        need(type(rows) is list and 0 < len(rows) <= 4096 and all(type(row) is dict and type(row.get('path')) is str for row in rows)
             and len({row['path'] for row in rows}) == len(rows), 'ui-source-roster')
        rows = {row['path']: row for row in rows}
        def source_body(relative):
            row = rows.get(relative)
            need(type(row) is dict and row.get('gitMode') == '100644' and type(row.get('size')) is int
                 and 0 < row['size'] <= 2 << 20, 'ui-source-row')
            body = original(SOURCE / relative, row['size'])
            need(len(body) == row['size'] and sha(body) == row.get('sha256')
                 and hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest() == row.get('blob'),
                 'ui-source-original')
            return body
        N, S, P = load_checkout_modules(clock)
        release_raw = source_body('desktop/macos-installed-inputs/' +
            ('build-release.json' if TARGET == 'aarch64-apple-darwin' else 'build-release-intel.json'))
        release = S.build_release_data(release_raw, target=TARGET)
        owner_raw = original(root / 'android-helper-package-install.json', 16384)
        owner = document(owner_raw)
        observed = document(original(root / 'installation-observation.json', 65536))
        final_raw = original(root / 'android-helper-finalize-package.json', 16384)
        need(type(owner.get('schemaVersion')) is int and owner['schemaVersion'] == 1 and owner.get('phase') == 'package-install'
             and owner.get('target') == TARGET and owner.get('packageRole') == 'ordinary-image'
             and all(owner.get(key) == env[variable] for key, variable in (('source', 'GITHUB_SHA'), ('workflowSource', 'GITHUB_WORKFLOW_SHA'),
                 ('workflow', 'GITHUB_WORKFLOW_REF'), ('runId', 'GITHUB_RUN_ID'), ('runAttempt', 'GITHUB_RUN_ATTEMPT')))
             and owner.get('imageSourceCommit') == source and owner.get('imageReleaseId') == release['release']
             and owner.get('imageReleaseSourceSha256') == sha(release_raw)
             and all(owner.get(key) is True for key in ('passed', 'targetRetired', 'originalClosesKnown', 'outerFinalityRequired'))
             and owner.get('cleanupErrors') == [] and owner.get('directStagerIOPending') is None
             and owner.get('finalPackageReceiptSha256') == sha(final_raw), 'ui-current-package-owner')
        package_originals(owner.get('originalCalls'), S.PACKAGING_CALL_ROLES)
        package_originals(owner.get('credentialOriginals'), ('producer-adhoc', 'producer-adhoc-verify', 'producer-cdhash')
            + (P.CREDENTIAL_ROLES[:17] + ('search-final', 'default-after')) * 3, credentials=True)
        contexts = owner.get('credentialContexts')
        need(type(contexts) is list and len(contexts) == 3 and all(type(row) is dict for row in contexts)
             and tuple(row.get('purpose') for row in contexts) == ('producer', 'distribution-image', 'observation-image')
             and all(all(row.get(key) is True for key in ('retired', 'closed', 'searchRestored', 'defaultUnchanged')) for row in contexts),
             'ui-package-credential-closes')
        need(owner.get('packageMount') == {'attachEntered': True, 'originalKnown': True, 'detached': True, 'retained': False,
             'installerEntered': True, 'installerOriginalZero': True, 'sameRequestV2Readback': True, 'systemServiceExitClaimed': False}
             and all(type(value) is bool for value in owner['packageMount'].values()), 'ui-package-mount')
        distribution = owner.get('distribution')
        need(type(distribution) is dict and type(distribution.get('schemaVersion')) is int and distribution['schemaVersion'] == 1
             and distribution.get('kind') == 'mrk-ordinary-package-observed-v2' and distribution.get('target') == TARGET
             and distribution.get('release') == release['release'] and distribution.get('packageVersion') == release['packageVersion']
             and type(distribution.get('packageBytes')) is int and 0 < distribution['packageBytes'] <= 512 << 20
             and S.maintenance_hex(distribution.get('packageSha256'), 64)
             and all(distribution.get(key) is True for key in ('originalInstallerReturnedZero', 'sameRequestV2Readback',
                  'originalMountDetached', 'groupEndpointMet', 'originalOuterReturnRequired')), 'ui-package-distribution')
        request = distribution.get('requestId')
        need(S.maintenance_hex(request, 32) and original(root / 'package-request-id.txt', 33) == (request + '\n').encode(),
             'ui-package-request')
        need(type(observed.get('schemaVersion')) is int and observed['schemaVersion'] == 2 and observed.get('requestId') == request
             and observed.get('sourceCommit') == source and observed.get('release') == release['release']
             and observed.get('completedPackageSha256') == distribution['packageSha256']
             and observed.get('originalInstallerReturnedZero') is True and observed.get('originalWriterJoined') is True
             and observed.get('historicalOuterExit') == 'unverified' and observed.get('applicationLaunched') is False
             and observed.get('guiSaveQualified') is False
             and observed.get('inventorySha256') == env['MRK_MACOS_INSTALL_INVENTORY_SHA256']
             and observed.get('runtimeManifestSha256') == binding.get('runtimeManifestSha256') == env['MRK_BUNDLED_RUNTIME_MANIFEST_SHA256'],
             'ui-same-request-readback')
        nested = S.maintenance_result_data(S.canonical(observed.get('originalInstallerResult')) + b'\n', request)
        need(nested['invocation'] == observed.get('invocation'), 'ui-installer-original-invocation')
        descriptor = original(root / 'producer-root/producer.json', 16384)
        signature = original(root / 'producer-root/producer.sig', 4096)
        producer = S.maintenance_producer_data(descriptor, target=TARGET)
        current = producer['releaseSet']['current']
        need(current['sourceCommit'] == source and current['release'] == release['release']
             and current['packageVersion'] == release['packageVersion'] and current['protocolSha256'] == S.CURRENT_PROTOCOL
             and current['inventorySha256'] == observed['inventorySha256'] and current['runtimeManifestSha256'] == observed['runtimeManifestSha256']
             and current['packageSha256'] == distribution['packageSha256']
             and distribution.get('descriptorSha256') == sha(descriptor) and distribution.get('signatureSha256') == sha(signature),
             'ui-current-producer-binding')
        signing = S.packaging_signing_data(source_body('desktop/packaging/macos-install-producer-signing.profile'),
                                         source_body('desktop/packaging/macos-android-service-signing.profile'))
        need(distribution.get('sourceProducerProfileSha256') == signing.producer_sha256
             and distribution.get('sourceServiceProfileSha256') == signing.service_sha256, 'ui-package-source-profiles')
        installer_profile = source_body('desktop/packaging/macos-installer-signing.json')
        installer_selection = P.installer_profile(installer_profile)
        need(installer_selection is not None, 'ui-configured-installer-source')
        P.final_package_receipt(final_raw, env, TARGET, installer_selection, sha(installer_profile),
            sha(source_body('desktop/packaging/macos-notary-service.json')), distribution['packageBytes'], distribution['packageSha256'],
            release['release'], sha(release_raw))
        audit = document(original(root / 'package-audit.json', 16384))
        need(audit.get('packageSha256') == distribution['packageSha256'] and type(audit.get('packageSize')) is int
             and audit['packageSize'] == distribution['packageBytes'] and audit.get('packageIdentifier') == 'dev.mobile-release-kit.desktop.installed'
             and audit.get('qualification') == 'scripts-only-package-audited-not-installed-or-GUI-qualified', 'ui-package-audit')
        facts = N.android_signed_facts(document(original(normal / 'android-signed-build.facts.json', 16384)),
                                       source=source, run=run, attempt=attempt, target=TARGET)
        build = document(original(normal / 'build.command-admission.json', 32768))
        test = document(original(normal / 'android-signed-build-test.runner-admission.json', 32768))
        summary = document(original(normal / 'android-signed-build-summary.command-admission.json', 32768))
        N.android_signed_receipts(build, test, summary, facts, source=source, normal=normal, run=run, attempt=attempt, target=TARGET)
        summary_raw = original(normal / 'android-signed-build-summary.json', 262144)
        summary_data = document(summary_raw)
        counts = {'totalTestCount': 1, 'passedTests': 1, 'failedTests': 0, 'skippedTests': 0, 'expectedFailures': 0}
        need(all(type(summary_data.get(key)) is int and summary_data[key] == count for key, count in counts.items())
             and summary['commands'][1]['stdoutBytes'] == len(summary_raw)
             and summary['commands'][1]['stdoutSha256'] == sha(summary_raw), 'ui-exact-original-one-pass')
        value = {'schemaVersion': 1, 'scope': 'ordinary-installed-one-android-signed-build-ui', 'target': TARGET,
            'applicationSourceCommit': source, 'harnessSourceCommit': source, 'sourceTree': binding['tree'],
            'workflow': '.github/workflows/desktop-macos-installed.yml', 'runId': run, 'runAttempt': attempt,
            'packageSha256': distribution['packageSha256'], 'packageBytes': distribution['packageBytes'],
            'runtimeManifestSha256': observed['runtimeManifestSha256'], 'installerInventorySha256': observed['inventorySha256'],
            'originalCommandStatuses': {'packageInstall': 0, 'installer': 0, 'supplier': 0, 'build': 0, 'test': 0, 'summary': 0},
            'testIdentifier': 'MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectAndroidSignedBuild', 'testCounts': counts,
            'observation': facts, 'resultOriginalReturncodeRequired': 0, 'privateInputsPublished': False,
            'vendorAcknowledgementAutomated': facts['vendorAcknowledgementAutomated'],
            'newProtectedCopyRegistered': facts['sourceRegistrationObserved'],
            'cleanExitStatus': None, 'allWorkerFinality': 'not-established-by-XCTest-UI-state',
            'fullUIQualified': False, 'distributionQualified': False, 'productReady': False}
        body = N.encoded(value) + b'\n'
        need(len(body) <= 16384, 'ui-public-envelope-bound')
        original_post()
        N.exclusive_output(normal / 'android-signed-build-result.json', body, 16384)
        original_post()
    except BaseException as error:
        primary = error
    finally:
        # Actual0 must follow all consuming closes.
        closing, held[:] = held[:], []
        for row in reversed(closing):
            try: os.close(row['fd'])
            except BaseException as error:
                if primary is None: primary = error
        try: clock()
        except BaseException as error:
            if primary is None: primary = error
    if primary is not None: raise primary


if __name__ == "__main__":
    main()
