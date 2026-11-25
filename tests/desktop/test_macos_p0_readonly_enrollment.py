"""Passive P0 DATA regression fixtures; no native/mount/Installer actions."""
import ast
import copy
import contextlib
import hashlib
import importlib.util
import io
import os
import json
from pathlib import Path
import stat
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile
import zlib

ROOT = Path(__file__).absolute().parents[2]


def load(name, leaf):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'desktop/tools' / leaf)
    value = importlib.util.module_from_spec(spec)
    prior = sys.modules.get(name); sys.modules[name] = value
    try:
        spec.loader.exec_module(value)
    finally:
        if prior is None: sys.modules.pop(name, None)
        else: sys.modules[name] = prior
    return value


DATA = load('_mrk_p0_enrollment_data', 'macos_p0_readonly_enrollment.py')
STAGER = load('_mrk_p0_enrollment_stager', 'stage_macos_installed.py')
UPDATE = load('_mrk_p0_enrollment_update', 'macos_update_verification.py')
PUBLIC = load('_mrk_p0_enrollment_public', 'macos_public_verification_evidence.py')
NATIVE = load('_mrk_p0_enrollment_native', 'macos_p0_readonly_native.py')


def odc(name, mode, body=b'', *, uid=0, links=1):
    encoded = name.encode('ascii') + b'\0'
    header = b'070707' + ('%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o' %
        (0, 1, mode, uid, 0, links, 0, 0, len(encoded), len(body))).encode('ascii')
    return header + encoded + body


def product(members):
    # Literal tiny compressed-TOC XAR shape; not a signed native package.
    tree, heap, cursor = {}, [], [20, 0]
    for path, body in members.items():
        node = tree; parts = path.split('/')
        for part in parts[:-1]: node = node.setdefault(part, {})
        node[parts[-1]] = body
    def record(name, value):
        cursor[1] += 1
        prefix = '<file id="' + str(cursor[1]) + '"><name>' + name + '</name>'
        if type(value) is dict:
            return prefix + '<type>directory</type>' + ''.join(record(k, v) for k, v in value.items()) + '</file>'
        start = cursor[0]; cursor[0] += len(value); heap.append(value)
        return prefix + '<type>file</type><data><length>' + str(len(value)) + '</length><offset>' + str(start) + '</offset><size>' + str(len(value)) + '</size><encoding style="application/octet-stream"/></data></file>'
    toc = ('<xar><toc><checksum style="sha1"><offset>0</offset><size>20</size></checksum>' + ''.join(record(k, v) for k, v in tree.items()) + '</toc></xar>').encode('ascii')
    packed = zlib.compress(toc)
    return struct.pack('>IHHQQI', 0x78617221, 28, 1, len(packed), len(toc), 1) + packed + hashlib.sha1(packed).digest() + b''.join(heap)


def fixture(target, *, bad_uid=False, duplicate=False):
    arch = 'arm64' if target == DATA.TARGETS[0] else 'x86_64'
    release_id = 'macos26-' + arch + '-desktop-01'; manifest = 'c' * 64
    names = ['app/' + STAGER.ENTRY_BINARY, 'app/' + STAGER.APP_BINARY, 'app/' + STAGER.VAULT_HELPER,
             'app/Contents/Info.plist', 'app/' + STAGER.PAYLOAD_INFO, 'runtime/python/bin/python3', 'runtime/manifest.json']
    executable = {'app/' + STAGER.ENTRY_BINARY, 'app/' + STAGER.APP_BINARY, 'app/' + STAGER.VAULT_HELPER, 'runtime/python/bin/python3'}
    rows = [{'path': name, 'size': 1, 'sha256': manifest if name == 'runtime/manifest.json' else 'b' * 64,
             'executable': name in executable} for name in sorted(names)]
    inventory = STAGER.canonical({'schemaVersion': 1, 'release': release_id, 'runtimeManifestSha256': manifest, 'files': rows})
    info = ('<pkg-info identifier="' + STAGER.PACKAGE_ID + '" version="0.1.1" install-location="/" auth="root"><payload numberOfFiles="0"/><scripts><postinstall file="./postinstall"/></scripts></pkg-info>').encode('ascii')
    scripts = odc('.', stat.S_IFDIR | 0o755) + odc('./input', stat.S_IFDIR | 0o555)
    scripts += odc('./input/' + STAGER.INSTALLATION_INVENTORY_NAME, stat.S_IFREG | 0o444, inventory, uid=1 if bad_uid else 0)
    if duplicate: scripts += odc('./input/' + STAGER.INSTALLATION_INVENTORY_NAME, stat.S_IFREG | 0o444, inventory)
    scripts += odc('TRAILER!!!', 0)
    package = product({'Distribution': b'fixed distribution', 'Resources/InstallerReadMe.html': b'fixed readme',
                       STAGER.INSTALL_COMPONENT + '/PackageInfo': info, STAGER.INSTALL_COMPONENT + '/Scripts': zlib.compress(scripts, wbits=31)})
    identity = {'teamIdentifier': '7CGZ2343AA', 'leafCertificateSha1': '5effa7d19bbe005b19c1617833cbe22186c2af96', 'leafCertificateSha256': '2' * 64}
    policy = {'schemaVersion': 1, 'kind': 'mrk-macos-developer-id-code-policy-v1', **identity, 'hardenedRuntime': True, 'entitlements': 'empty'}
    ph = DATA.sha(json.dumps(policy, separators=(',', ':')).encode('ascii'))
    release = {'profile': 'fixed-macos26-' + arch + '-maintenance-v2', 'packageIdentifier': STAGER.PACKAGE_ID,
               'bundleIdentifier': STAGER.BUNDLE_ID, 'packageVersion': '0.1.1', 'release': release_id, 'sourceCommit': 'a' * 40,
               'protocolSha256': STAGER.CURRENT_PROTOCOL, 'runtimeManifestSha256': manifest, 'inventorySha256': DATA.sha(inventory),
               'signingPolicySha256': ph, 'packageSha256': DATA.sha(package)}
    descriptor = STAGER.canonical({'schemaVersion': 2, 'kind': 'mrk-macos-install-producer-v2', 'domain': 'MobileReleaseKit-package-producer-v2',
                 'target': target, 'releaseSet': {'schemaVersion': 2, 'current': release, 'acceptedPredecessors': []},
                 'signingPolicies': [{'sha256': ph, 'policy': policy}]}) + b'\n'
    bodies = {'Install.pkg': package, 'producer.json': descriptor, 'producer.sig': b'INERT NOT A SIGNATURE\n'}
    bind = lambda name, body: {'name': name, 'bytes': len(body), 'sha256': DATA.sha(body)}
    row = {'source': 'a' * 40, 'tree': 'b' * 40, 'runId': '123', 'runAttempt': '1', 'jobId': '456', 'artifactId': '789',
           'artifactBytes': 100, 'artifactSha256': 'e' * 64, 'qualificationEvidenceSha256': 'f' * 64,
           'qualificationArtifact': {'artifactId': '790', 'artifactBytes': 200, 'artifactSha256': 'e' * 64,
               'memberName': 'public-verification-evidence.json', 'memberBytes': 100, 'memberSha256': 'f' * 64},
           'members': [bind(name, name.encode()) for name in DATA.MEMBERS], 'package': bind('Install.pkg', package),
           'descriptor': bind('producer.json', descriptor), 'signature': bind('producer.sig', bodies['producer.sig']),
           'inventorySha256': DATA.sha(inventory), 'runtimeManifestSha256': manifest, 'packageVersion': '0.1.1', 'release': release_id,
           'signingIdentity': identity}
    return row, {k: (v, 0o444) for k, v in bodies.items()}, inventory


class P0EnrollmentDataTests(unittest.TestCase):
    def test_original_entry_clock_is_consumed_without_restart(self):
        with mock.patch.object(NATIVE, '_ENTRY_STARTED_NS', 10), \
             mock.patch.object(NATIVE, 'Deadline') as clock, \
             mock.patch.object(NATIVE.sys, 'platform', 'linux'), \
             mock.patch.object(NATIVE.os, 'mkdir') as mkdir:
            with self.assertRaisesRegex(NATIVE.Refused, '^p0-host-context$'):
                NATIVE.main()
            clock.assert_called_once_with(started=10)
            mkdir.assert_not_called()
            self.assertEqual(NATIVE._ENTRY_STARTED_NS, 10)
        for invalid in (None, True, 0):
            with mock.patch.object(NATIVE, '_ENTRY_STARTED_NS', invalid), \
                 mock.patch.object(NATIVE, 'Deadline') as clock:
                with self.assertRaisesRegex(NATIVE.Refused, '^p0-original-start$'):
                    NATIVE.main()
                clock.assert_not_called()

    def test_original_public_anchors_and_root0_inventory_precede_observed_capacity(self):
        self.assertEqual(DATA.MEMBERS, ('MobileReleaseKit.dmg', 'PREVIEW.json'))
        self.assertEqual(DATA.ROLES, ('finalize-package', 'package-install', 'finalize-image'))
        with self.assertRaisesRegex(DATA.Refused, 'unconfigured'):
            DATA.anchors_data({'schemaVersion': 1, 'mode': 'unconfigured'}, DATA.TARGETS[0], STAGER)
        for target in DATA.TARGETS:
            row, originals, inventory = fixture(target)
            document = {'schemaVersion': 1, 'mode': 'configured', 'targets': {selected: fixture(selected)[0] for selected in DATA.TARGETS}}
            self.assertEqual(DATA.anchors_data(document, target, STAGER), row)
            context = {k: row[k] for k in ('source', 'runId', 'runAttempt')}
            context.update(workflowSource=row['source'], target=target)
            preview = {'schemaVersion': 2, 'scope': 'normal-macos-early-preview', 'sourceCommit': row['source'],
                'sourceTree': row['tree'], 'runId': row['runId'], 'runAttempt': row['runAttempt'],
                'platform': 'macOS26-arm64' if target == DATA.TARGETS[0] else 'macOS26-x86_64',
                'packageSha256': row['package']['sha256'], 'packageSize': row['package']['bytes'],
                'descriptorSha256': row['descriptor']['sha256'], 'signatureSha256': row['signature']['sha256'],
                'runtimeManifestSha256': row['runtimeManifestSha256'], 'installerInventorySha256': row['inventorySha256']}
            preview.update({k: True for k in ('originalInstallerReturnedZero', 'originalPackageGroupReturnedZero',
                'originalObservationMountDetached', 'originalImageFinalizationReturnedZero', 'originalFinalImageMountDetached', 'finalImageScopedNotarizationObserved')})
            artifact = {name: name.encode('ascii') for name in DATA.MEMBERS}
            preview.update(distributionBytes=len(artifact[DATA.MEMBERS[0]]), distributionSha256=DATA.sha(artifact[DATA.MEMBERS[0]]))
            artifact['PREVIEW.json'] = STAGER.canonical(preview)
            selected_row = copy.deepcopy(row)
            selected_row['members'] = [{'name': name, 'bytes': len(artifact[name]), 'sha256': DATA.sha(artifact[name])} for name in DATA.MEMBERS]
            deliveries = {'preview': PUBLIC.project_summary(preview, context, False)}
            phase = {'receiptState': 'observed', 'recordedPassed': True, 'correlationMatches': True,
                'originalClosesKnown': True, 'targetRetired': True, 'outerFinalityRequired': True, 'failure': None,
                'originalCalls': {'unclassifiedCount': 0, 'calls': [{'role': 'inert-data-original', 'entered': True, 'returned': True,
                    'capturesSettled': True, 'returncode': 0}]}, 'credentialContexts': []}
            qualification = {'schemaVersion': 1, 'kind': 'mrk-public-verification-evidence-v1', 'diagnosticOnly': True,
                'productReady': False, 'profile': 'installed', **context, 'sourceInventory': {'receiptState': 'observed', 'tree': row['tree']},
                'phases': {name: copy.deepcopy(phase) for name in DATA.ROLES}, 'deliveries': deliveries}
            public_body = STAGER.canonical(qualification)
            selected_row['qualificationEvidenceSha256'] = DATA.sha(public_body)
            selected_row['qualificationArtifact'].update(memberBytes=len(public_body), memberSha256=DATA.sha(public_body))
            actual_context, actual_deliveries = DATA.qualification_data(public_body, selected_row, target, STAGER, PUBLIC)
            self.assertEqual((actual_context, actual_deliveries), (context, deliveries))
            self.assertEqual(DATA.artifact_data(artifact, selected_row, context, deliveries, STAGER, PUBLIC), artifact[DATA.MEMBERS[0]])
            for fault in ('hash', 'failed', 'unknown', 'wrong-target', 'unretired', 'wrong-source'):
                bad = copy.deepcopy(qualification); nomination_row = copy.deepcopy(selected_row)
                if fault == 'hash': nomination_row['qualificationEvidenceSha256'] = '9' * 64
                elif fault == 'failed': bad['phases']['package-install']['recordedPassed'] = False
                elif fault == 'unknown': bad['phases']['package-install']['originalCalls']['calls'][0]['returned'] = False
                elif fault == 'wrong-target': bad['target'] = DATA.TARGETS[1] if target == DATA.TARGETS[0] else DATA.TARGETS[0]
                elif fault == 'unretired': bad['phases']['finalize-image']['targetRetired'] = False
                else: bad['source'] = '9' * 40
                encoded = STAGER.canonical(bad)
                if fault != 'hash': nomination_row['qualificationEvidenceSha256'] = DATA.sha(encoded)
                with self.subTest(qualification=fault), self.assertRaises(DATA.Refused):
                    DATA.qualification_data(encoded, nomination_row, target, STAGER, PUBLIC)
            for fault in ('extra', 'hash', 'old-nested', 'injected-removal', 'self-consistent-wrong-package'):
                bad = dict(artifact); selected = copy.deepcopy(selected_row); expected = deliveries
                if fault == 'extra': bad['extra'] = b'not a delivery member'
                elif fault == 'hash': bad[DATA.MEMBERS[0]] += b' '
                elif fault == 'old-nested': bad = {'preview/' + key: body for key, body in bad.items()}
                elif fault == 'injected-removal': bad['remove-preview/REMOVAL.json'] = b'not a P0 installation input'
                else:
                    altered = dict(preview, packageSha256='9' * 64)
                    bad['PREVIEW.json'] = STAGER.canonical(altered)
                    selected['members'][1].update(bytes=len(bad['PREVIEW.json']), sha256=DATA.sha(bad['PREVIEW.json']))
                    expected = dict(deliveries, preview=PUBLIC.project_summary(altered, context, False))
                with self.subTest(artifact=fault), self.assertRaises(DATA.Refused):
                    DATA.artifact_data(bad, selected, context, expected, STAGER, PUBLIC)
            # The old nested6 route is specifically refused by enrollment,
            # while the independent update parser retains its historical map.
            nested = copy.deepcopy(document)
            nested['targets'][target]['members'] = [
                {'name': name, 'bytes': len(name), 'sha256': '9' * 64}
                for name in UPDATE.ARTIFACT_PATHS]
            with self.assertRaises(DATA.Refused): DATA.anchors_data(nested, target, STAGER)
            result, actual = DATA.mounted_data(originals, row, target, STAGER)
            self.assertEqual(actual, inventory)
            self.assertEqual(result['inventory']['bytes'], len(inventory))
            self.assertEqual(result['inventoryFiles'], 7)
            self.assertIs(result['nativeQualificationInferred'], False)
            for fault in ('package-hash', 'manifest', 'inventory', 'source', 'target', 'mode', 'extra', 'descriptor'):
                selected = copy.deepcopy(row); changed = dict(originals); selected_target = target
                if fault == 'package-hash': selected['package']['sha256'] = '9' * 64
                elif fault == 'manifest': selected['runtimeManifestSha256'] = '9' * 64
                elif fault == 'inventory': selected['inventorySha256'] = '9' * 64
                elif fault == 'source': selected['source'] = '9' * 40
                elif fault == 'target': selected_target = DATA.TARGETS[1] if target == DATA.TARGETS[0] else DATA.TARGETS[0]
                elif fault == 'mode': changed['Install.pkg'] = (changed['Install.pkg'][0], 0o644)
                elif fault == 'extra': changed['extra'] = (b'not a product', 0o444)
                else: changed['producer.json'] = (b'{}', 0o444)
                with self.subTest(target=target, fault=fault), self.assertRaises((DATA.Refused, STAGER.Refused)):
                    DATA.mounted_data(changed, selected, selected_target, STAGER)
            for bad_uid, duplicate in ((True, False), (False, True)):
                badrow, badoriginals, _ = fixture(target, bad_uid=bad_uid, duplicate=duplicate)
                with self.assertRaises(STAGER.Refused): DATA.mounted_data(badoriginals, badrow, target, STAGER)
            value = STAGER.decode(inventory); value.update(release=row['release'].replace('-01', '-02'))
            new_inventory = STAGER.canonical(value)
            current = {'source': 'd' * 40, 'runtimeManifestSha256': row['runtimeManifestSha256'], 'inventorySha256': DATA.sha(new_inventory),
                       'packageVersion': '0.1.2', 'release': value['release']}
            capacity = DATA.prospective_capacity_data(result, inventory, new_inventory, current, target, STAGER, UPDATE)
            self.assertEqual(capacity['declaredFiles'], 16)
            self.assertIs(capacity['finalizedPairDataStillRequired'], True)
            self.assertIs(capacity['updateActivated'], False)
            with self.assertRaises(DATA.Refused): DATA.prospective_capacity_data(result, inventory + b' ', new_inventory, current, target, STAGER, UPDATE)
            oversized = STAGER.decode(new_inventory)
            for item in oversized['files']: item['size'] = STAGER.MAX_BYTES // len(oversized['files'])
            huge = STAGER.canonical(oversized); binding = dict(current, inventorySha256=DATA.sha(huge))
            with self.assertRaises(ValueError): DATA.prospective_capacity_data(result, inventory, huge, binding, target, STAGER, UPDATE)

        # This is the same grouped contract: network/mount ports below are DATA
        # only. No process, socket, mounted image or native library is entered.
        old_state = dict(NATIVE.STATE)
        try:
            for key, value in old_state.items(): NATIVE.STATE[key] = value
            target = DATA.TARGETS[0]
            row = fixture(target)[0]
            partial = {'schemaVersion': 1, 'mode': 'configured', 'targets': {target: row, DATA.TARGETS[1]: {'mode': 'unconfigured'}}}
            self.assertEqual(NATIVE.qualified_rows_data(partial, DATA, STAGER), [(target, row)])
            with self.assertRaisesRegex(DATA.Refused, 'target-unconfigured'): DATA.anchors_data(partial, DATA.TARGETS[1], STAGER)
            empty = copy.deepcopy(partial); empty['targets'][target] = {'mode': 'unconfigured'}
            with self.assertRaises(NATIVE.Refused): NATIVE.qualified_rows_data(empty, DATA, STAGER)
            for key, replacement in (('artifactId', row['artifactId']), ('artifactBytes', (256 << 10) + 1),
                                     ('memberBytes', (128 << 10) + 1), ('memberSha256', '9' * 64),
                                     ('memberName', 'private.json')):
                doc = {'schemaVersion': 1, 'mode': 'configured', 'targets': {v: fixture(v)[0] for v in DATA.TARGETS}}
                doc['targets'][target]['qualificationArtifact'][key] = replacement
                with self.subTest(qualificationAnchor=key), self.assertRaises(DATA.Refused):
                    DATA.anchors_data(doc, target, STAGER)

            # Exact closed run/attempt/source/job and outer artifact authority.
            run = {'id': 123, 'run_attempt': 1, 'head_sha': row['source'], 'head_branch': 'verify/desktop-macos-installed',
                   'path': NATIVE.WORKFLOW, 'workflow_id': NATIVE.WORKFLOW_ID, 'status': 'completed',
                   'repository': {'full_name': NATIVE.REPOSITORY}}
            job = {'id': 456, 'run_id': 123, 'head_sha': row['source'], 'status': 'completed', 'conclusion': 'success',
                   'steps': [{'status': 'completed', 'conclusion': 'success'}]}
            for role in ('qualification', 'carrier'):
                nominated = row['qualificationArtifact'] if role == 'qualification' else row
                name = ('desktop-macos-installed-' + target + '-' + row['source'] + '-123-1' if role == 'qualification'
                        else 'mobile-release-kit-macos26-' + target + '-p0-carrier-input-' + row['source'] + '-123-1')
                outer = {'id': int(nominated['artifactId']), 'name': name, 'expired': False,
                         'size_in_bytes': nominated['artifactBytes'], 'digest': 'sha256:' + nominated['artifactSha256'],
                         'workflow_run': {'id': 123, 'head_sha': row['source'], 'head_branch': run['head_branch']}}
                self.assertEqual(NATIVE.metadata_data(run, job, outer, row, role, target), nominated)
                for fault in ('attempt', 'source', 'workflow', 'open-job', 'failed-job', 'open-step', 'artifact-id',
                              'artifact-name', 'expired', 'size', 'digest', 'artifact-source'):
                    r, j, a = copy.deepcopy(run), copy.deepcopy(job), copy.deepcopy(outer)
                    if fault == 'attempt': r['run_attempt'] = 2
                    elif fault == 'source': r['head_sha'] = '9' * 40
                    elif fault == 'workflow': r['workflow_id'] += 1
                    elif fault == 'open-job': j['status'] = 'in_progress'
                    elif fault == 'failed-job': j['conclusion'] = 'failure'
                    elif fault == 'open-step': j['steps'][0]['status'] = 'in_progress'
                    elif fault == 'artifact-id': a['id'] += 10
                    elif fault == 'artifact-name': a['name'] = 'other-target-private-artifact'
                    elif fault == 'expired': a['expired'] = True
                    elif fault == 'size': a['size_in_bytes'] += 1
                    elif fault == 'digest': a['digest'] = 'sha256:' + '9' * 64
                    else: a['workflow_run']['head_sha'] = '9' * 40
                    with self.subTest(metadataRole=role, fault=fault), self.assertRaises(NATIVE.Refused):
                        NATIVE.metadata_data(r, j, a, row, role, target)
            good = 'https://account.blob.core.windows.net/fixed.zip?sig=not-a-credential'
            self.assertEqual(NATIVE.redirect_data(good), good)
            for address in ('http://account.blob.core.windows.net/a', 'https://account.blob.core.windows.net.evil/a',
                            'https://user@account.blob.core.windows.net/a', 'https://account.blob.core.windows.net:444/a',
                            'https://account.blob.core.windows.net/a#fragment', 'https://other.example/a'):
                with self.subTest(redirect=address), self.assertRaises(NATIVE.Refused): NATIVE.redirect_data(address)
            api = NATIVE.request_headers(authenticated=True, token='synthetic-read-token')
            blob = NATIVE.request_headers(authenticated=False, token='synthetic-read-token')
            self.assertEqual(api['Authorization'], 'Bearer synthetic-read-token')
            self.assertNotIn('Authorization', blob)
            self.assertIsNone(NATIVE.NoRedirect().redirect_request(None, None, 302, None, None, good))

            # Actual acquisition control flow, ordinary API DATA ports only.
            # No opener, socket, CA library or filesystem operation escapes these ports.
            transfer = b'bounded original artifact stream'
            for mode in ('success', 'oversize', 'wrong-digest', 'truncated', 'late',
                         'read-primary-close-failure', 'digest-primary-close-failure', 'final-close-failure'):
                with self.subTest(acquisitionControlFlow=mode):
                    nominated_row = copy.deepcopy(row)
                    nominated_row.update(artifactBytes=len(transfer), artifactSha256=DATA.sha(transfer))
                    artifact = {'id': int(row['artifactId']),
                        'name': 'mobile-release-kit-macos26-' + target + '-p0-carrier-input-' + row['source'] + '-123-1',
                        'expired': False, 'size_in_bytes': len(transfer), 'digest': 'sha256:' + DATA.sha(transfer),
                        'workflow_run': {'id': 123, 'head_sha': row['source'], 'head_branch': run['head_branch']}}
                    work = '/Users/runner/work/_temp/mrk-p0-readonly-inert'
                    ca = b'INERT trust DATA, never parsed by OpenSSL'
                    written, close_calls, requests, responses = bytearray(), [], [], []
                    uid, gid = 501, 20
                    def info(kind, size=0):
                        return SimpleNamespace(st_dev=1, st_ino={'ca': 2, 'root': 3, 'output': 4}[kind],
                            st_mode=(stat.S_IFDIR | 0o700 if kind == 'root' else stat.S_IFREG | (0o444 if kind == 'ca' else 0o600)),
                            st_uid=0 if kind == 'ca' else uid, st_gid=0 if kind == 'ca' else gid,
                            st_nlink=1, st_size=len(ca) if kind == 'ca' else size,
                            st_mtime_ns=10, st_ctime_ns=11)
                    root_info = info('root')
                    original_read_failure = OSError('INERT primary read must not be replaced or published')
                    class Response:
                        def __init__(self, code, body=b'', headers=(), *, blob=False):
                            self.code, self.body, self.at, self.blob, self.closes = code, body, 0, blob, 0
                            self.headers = SimpleNamespace(items=lambda: list(headers))
                            responses.append(self)
                        def read(self, amount):
                            self_outer.assertTrue(0 < amount <= 65536)
                            if self.blob and mode == 'read-primary-close-failure': raise original_read_failure
                            block = self.body[self.at:self.at + amount]; self.at += len(block); return block
                        def close(self):
                            self.closes += 1
                            self_outer.assertEqual(self.closes, 1)
                            if self.blob and mode in ('read-primary-close-failure', 'digest-primary-close-failure'):
                                raise OSError('INERT response cleanup must remain a finite note')
                    self_outer = self
                    blob_body = (transfer + b'X' if mode == 'oversize' else b'X' * len(transfer)
                                 if mode in ('wrong-digest', 'digest-primary-close-failure') else
                                 transfer[:-1] if mode == 'truncated' else transfer)
                    sequence = [Response(200, NATIVE.canonical(run)), Response(200, NATIVE.canonical(job)),
                        Response(200, NATIVE.canonical(artifact)), Response(302, headers=(('Location', good),)),
                        Response(200, blob_body, (('Content-Length', str(len(transfer))),), blob=True)]
                    class Opener:
                        def open(self, request, timeout):
                            requests.append(request)
                            self_outer.assertTrue(0 < timeout <= 10)
                            return sequence[len(requests) - 1]
                    def open_port(path, flags, mode_arg=0o777, *, dir_fd=None):
                        if path == '/fixed/ca.pem':
                            self.assertTrue(flags & os.O_NOFOLLOW); self.assertIsNone(dir_fd); return 10
                        if path == work:
                            self.assertTrue(flags & os.O_DIRECTORY); self.assertIsNone(dir_fd); return 11
                        self.assertEqual(path, 'arm64-carrier.zip'); self.assertEqual(dir_fd, 11)
                        self.assertEqual(mode_arg, 0o600); self.assertTrue(flags & os.O_EXCL and flags & os.O_NOFOLLOW); return 12
                    def fstat_port(fd):
                        return info('ca') if fd == 10 else root_info if fd == 11 else info('output', len(written))
                    def stat_port(path, *, dir_fd=None, follow_symlinks=True):
                        self.assertFalse(follow_symlinks)
                        if path == '/fixed/ca.pem': return info('ca')
                        if path == work: return root_info
                        self.assertEqual((path, dir_fd), ('arm64-carrier.zip', 11)); return info('output', len(written))
                    def pread_port(fd, amount, offset):
                        body = ca if fd == 10 else bytes(written)
                        return body[offset:offset + amount]
                    def write_port(fd, body):
                        self.assertEqual(fd, 12); count = min(3, len(body)); written.extend(body[:count]); return count
                    def close_port(fd):
                        close_calls.append(fd); self.assertEqual(close_calls.count(fd), 1)
                        if fd == 11 and mode in ('digest-primary-close-failure', 'final-close-failure'):
                            raise OSError('INERT original close must remain a finite note')
                    def time_port():
                        return 2.0 if mode == 'late' and sequence[-1].at == len(blob_body) else 0.0
                    request_cfg = {'row': nominated_row, 'role': 'carrier', 'target': target, 'work': work,
                        'workIdentity': list(NATIVE.identity(root_info)[:5]), 'caPath': '/fixed/ca.pem',
                        'caSha256': DATA.sha(ca), 'endpoint': 1_000_000_000}
                    tls = SimpleNamespace(check_hostname=True, verify_mode=NATIVE.ssl.CERT_REQUIRED)
                    with contextlib.ExitStack() as stack:
                        stack.enter_context(mock.patch.dict(NATIVE.os.environ, {'MRK_P0_REQUEST': NATIVE.canonical(request_cfg).decode(),
                            'MRK_P0_READ_TOKEN': 'INERT TOKEN NEVER FORWARDED'}, clear=True))
                        for name, value in (('open', open_port), ('fstat', fstat_port), ('stat', stat_port),
                            ('pread', pread_port), ('write', write_port), ('fsync', lambda fd: None), ('close', close_port),
                            ('getuid', lambda: uid), ('getgid', lambda: gid)):
                            stack.enter_context(mock.patch.object(NATIVE.os, name, value))
                        stack.enter_context(mock.patch.object(NATIVE.time, 'monotonic_ns', lambda: 1))
                        stack.enter_context(mock.patch.object(NATIVE.time, 'monotonic', time_port))
                        stack.enter_context(mock.patch.object(NATIVE.ssl, 'create_default_context', return_value=tls))
                        stack.enter_context(mock.patch.object(NATIVE.urllib.request, 'build_opener', return_value=Opener()))
                        error = None
                        try: result = NATIVE.acquisition_main()
                        except BaseException as caught: error = caught
                    self.assertEqual(close_calls, [10, 12, 11])
                    self.assertEqual(len(requests), 5)
                    self.assertTrue(all(response.closes == 1 for response in responses))
                    for request in requests[:4]:
                        self.assertEqual(request.get_header('Authorization'), 'Bearer INERT TOKEN NEVER FORWARDED')
                    self.assertIsNone(requests[-1].get_header('Authorization'))
                    self.assertEqual(requests[-1].full_url, good)
                    self.assertEqual(tls.minimum_version, NATIVE.ssl.TLSVersion.TLSv1_2)
                    if mode == 'success':
                        self.assertIsNone(error); self.assertEqual(bytes(written), transfer)
                        self.assertEqual(result, {'schemaVersion': 1, 'role': 'carrier', 'target': target,
                            'bytes': len(transfer), 'sha256': DATA.sha(transfer), 'closedMetadataMatched': True, 'originalClosesKnown': True})
                    else:
                        expected = ('p0-artifact-bound' if mode == 'oversize' else 'p0-child-post-deadline' if mode == 'late'
                                    else 'p0-child-close-unknown' if mode == 'final-close-failure' else 'p0-artifact-digest')
                        if mode == 'read-primary-close-failure': self.assertIs(error, original_read_failure)
                        else: self.assertIs(type(error), NATIVE.Refused); self.assertEqual(error.args, (expected,))
                        if mode in ('read-primary-close-failure', 'digest-primary-close-failure'):
                            self.assertEqual(error.__notes__, ['p0-child-close-unknown'])
                        self.assertNotIn('INERT', json.dumps(NATIVE.failure_data(error)))

            # Bootstrap consumes its one original close without replacing a
            # simultaneous source refusal, and cannot execute after unknown close.
            donor_body = b'Originals = None\n'  # Bounded checkout code, not a static hash fixture.
            for mode in ('success', 'source-primary-close-failure', 'close-failure',
                         'oversize', 'empty', 'nonregular', 'owner', 'links', 'writable', 'changed', 'short'):
                donor_info = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o644,
                    st_uid=501, st_gid=20, st_nlink=1, st_size=len(donor_body), st_mtime_ns=1, st_ctime_ns=1)
                if mode == 'oversize': donor_info.st_size = NATIVE.MODULE_SOURCE_LIMIT + 1
                elif mode == 'empty': donor_info.st_size = 0
                elif mode == 'nonregular': donor_info.st_mode = stat.S_IFDIR | 0o755
                elif mode == 'owner': donor_info.st_uid = 502
                elif mode == 'links': donor_info.st_nlink = 2
                elif mode == 'writable': donor_info.st_mode |= 0o002
                named_info = copy.copy(donor_info)
                if mode == 'changed': named_info.st_ino += 1
                close_calls = []
                def bootstrap_close(fd):
                    close_calls.append(fd)
                    if mode in ('source-primary-close-failure', 'close-failure'): raise OSError('INERT unknown bootstrap close')
                with mock.patch.object(NATIVE.os, 'open', return_value=10), \
                     mock.patch.object(NATIVE.os, 'fstat', return_value=donor_info), \
                     mock.patch.object(NATIVE.os, 'stat', return_value=named_info), \
                     mock.patch.object(NATIVE.os, 'getuid', return_value=501), \
                     mock.patch.object(NATIVE.os, 'pread', return_value=b'' if mode == 'short' else donor_body + (b'X' if mode == 'source-primary-close-failure' else b'')), \
                     mock.patch.object(NATIVE.os, 'close', side_effect=bootstrap_close), \
                     mock.patch.object(NATIVE, 'load_module', return_value=SimpleNamespace(Originals='INERT borrowed factory')) as loader:
                    if mode == 'success': self.assertEqual(NATIVE.bootstrap_originals(ROOT), 'INERT borrowed factory')
                    else:
                        with self.assertRaises(NATIVE.Refused) as caught: NATIVE.bootstrap_originals(ROOT)
                        expected = ('p0-bootstrap-close-unknown' if mode == 'close-failure' else
                                    'p0-bootstrap-source' if mode in ('source-primary-close-failure', 'changed', 'short') else
                                    'p0-bootstrap-original')
                        self.assertEqual(caught.exception.args, (expected,))
                        if mode == 'source-primary-close-failure': self.assertEqual(caught.exception.__notes__, ['p0-bootstrap-close-unknown'])
                self.assertEqual(close_calls, [10]); self.assertEqual(loader.call_count, int(mode == 'success'))

            # Real in-memory ZIP bytes and reviewed codec, not extraction mocks.
            def packed(members, *, compression=zipfile.ZIP_STORED, streaming=False):
                class Sink(io.BytesIO):
                    def seekable(self): return False
                    def seek(self, *args): raise io.UnsupportedOperation('fixture unseekable')
                sink = Sink() if streaming else io.BytesIO()
                with zipfile.ZipFile(sink, 'w', compression=compression) as archive:
                    for name, body in members.items(): archive.writestr(name, body)
                return sink.getvalue()
            def selection(body, members, kind):
                return {'kind': kind, 'bytes': len(body), 'sha256': DATA.sha(body),
                        'members': [{'name': name, 'bytes': len(value), 'sha256': DATA.sha(value)} for name, value in members.items()]}
            clock = NATIVE.Deadline(lambda: 1)
            members = {'MobileReleaseKit.dmg': b'synthetic unsigned DATA image', 'PREVIEW.json': b'{}'}
            for kind, inputs in (('carrier', members), ('qualification', {'public-verification-evidence.json': b'{}'})):
                for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    for streaming in (False, True):
                        body = packed(inputs, compression=compression, streaming=streaming)
                        self.assertEqual(NATIVE.zip_data(body, selection(body, inputs, kind), clock), inputs)
            body = packed(members)
            for fault in ('sha', 'truncate', 'trailing', 'extra', 'nested', 'wrong-member-sha', 'crc', 'local-size', 'gap'):
                bad = body; chosen = selection(body, members, 'carrier')
                if fault == 'sha': chosen['sha256'] = '9' * 64
                elif fault == 'truncate': bad = body[:-1]
                elif fault == 'trailing': bad = body + b'x'
                elif fault == 'extra': bad = packed(dict(members, **{'private.txt': b'never public'}))
                elif fault == 'nested': bad = packed({'preview/' + k: v for k, v in members.items()})
                elif fault == 'wrong-member-sha': chosen['members'][0]['sha256'] = '9' * 64
                elif fault == 'crc':
                    changed = bytearray(body); changed[30 + len('MobileReleaseKit.dmg')] ^= 1; bad = bytes(changed)
                elif fault == 'local-size':
                    changed = bytearray(body); struct.pack_into('<L', changed, 22, len(members['MobileReleaseKit.dmg']) + 1); bad = bytes(changed)
                else:
                    # Maintain central offsets after an injected unaccounted gap.
                    e = struct.unpack('<4s4H2LH', body[-22:]); start = e[6]
                    changed = bytearray(body[:start] + b'x' + body[start:]); struct.pack_into('<L', changed, len(changed) - 6, start + 1); bad = bytes(changed)
                if fault not in ('sha', 'wrong-member-sha'):
                    chosen.update(bytes=len(bad), sha256=DATA.sha(bad))
                with self.subTest(zip=fault), self.assertRaises((ValueError, zipfile.BadZipFile, struct.error)):
                    NATIVE.zip_data(bad, chosen, clock)
            # An otherwise coherent DEFLATE span with codec-tail bytes refuses
            # before logical ZipExtFile could hide them.
            raw = zlib.compress(b'abc')[2:-4] + b'X'
            info = SimpleNamespace(filename='PREVIEW.json', compress_size=len(raw), file_size=3,
                                   compress_type=zipfile.ZIP_DEFLATED, CRC=zlib.crc32(b'abc'))
            with self.assertRaises(NATIVE.Refused): NATIVE.member_stream_complete(io.BytesIO(raw), info, 0, len(raw), clock)

            # A global reservation is made before the real donor call can open.
            class Book:
                def __init__(self): self.entries, self.directories, self.errors, self.calls = [], {}, [], []
                def directory(self, path):
                    path = Path(path)
                    if path in self.directories: return self.directories[path]
                    if path != Path('/'): self.directory(path.parent)
                    entry = {'path': path, 'kind': 'directory', 'fd': len(self.entries) + 100, 'closed': False}
                    self.entries.append(entry); self.directories[path] = entry; self.calls.append(path)
                    return entry
                def file(self, path, *args, **kwargs):
                    self.directory(Path(path).parent)
                    entry = {'path': path, 'kind': 'file', 'fd': 101, 'closed': False}
                    self.entries.append(entry); self.calls.append(path); return entry, b'x'
                def check_one(self, entry): pass
                def check(self): pass
                def finish(self):
                    for entry in self.entries: entry['fd'] = None; entry['closed'] = True
                    return not self.errors
            quota = NATIVE.OriginalQuota(); book = quota.book(Book)
            quota.call(book, 'file', Path('/held/a/input'), 1)
            self.assertEqual(quota.reserved, 4)
            self.assertEqual(len(book.entries), 4)
            quota.reserve(92)
            prior = list(book.calls)
            with self.assertRaises(NATIVE.Refused): quota.call(book, 'file', Path('/new/input'), 1)
            self.assertEqual(book.calls, prior)  # No donor/open was entered.
            self.assertEqual(quota.reserved, 96)
            quota2 = NATIVE.OriginalQuota(); b2 = quota2.book(Book)
            def failed(*args, **kwargs): raise OSError('synthetic original admission failure')
            b2.file = failed
            with self.assertRaises(OSError): quota2.call(b2, 'file', Path('/a/input'), 1)
            self.assertEqual(quota2.reserved, 3)  # Exception never refunds.
            quota3 = NATIVE.OriginalQuota(); b3 = quota3.book(Book)
            b3.file = lambda *args, **kwargs: (None, b'x')
            with self.assertRaisesRegex(NATIVE.Refused, 'quote-correspondence'):
                quota3.call(b3, 'file', Path('/a/input'), 1)
            self.assertEqual(quota3.reserved, 3)
            session = NATIVE.Enrollment(Path('/source'), Path('/held/work'), clock, Book)
            session.outer.directory(Path('/unrelated/source'))
            borrowed = session.fresh_book()
            self.assertEqual(set(borrowed.directories), set(Path('/held/work').parents) | {Path('/held/work')})
            self.assertNotIn(Path('/unrelated/source'), borrowed.directories)
            for path, entry in borrowed._p0_borrowed:
                self.assertIs(entry, session.outer.directories[path]); self.assertNotIn(entry, borrowed.entries)
            self.assertTrue(borrowed.finish())
            self.assertTrue(all(entry['fd'] is not None for _, entry in borrowed._p0_borrowed))
            borrowed.directories[Path('/held/work')] = dict(session.parent)
            with self.assertRaisesRegex(NATIVE.Refused, 'borrowed-parent'): session.quota.check()

            sample = b'Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free:  100.\nPages inactive: 200.\nPages speculative:  50.\n'
            memory = NATIVE.memory_data(sample, b'', 0, page_size=4096, physical_bytes=16 << 30)
            self.assertEqual(memory['availableEstimateBytes'], 350 * 4096)
            self.assertIs(memory['osMemoryReservation'], False); self.assertIs(memory['peakRssQualified'], False)
            for bad, page, physical in ((sample + b'Pages free: 1.\n', 4096, 16 << 30),
                                        (sample.replace(b'200.', b'-2.'), 4096, 16 << 30),
                                        (sample.replace(b'Pages speculative:  50.\n', b''), 4096, 16 << 30),
                                        (sample, 16384, 16 << 30), (sample, 4096, 1)):
                with self.assertRaises(NATIVE.Refused): NATIVE.memory_data(bad, b'', 0, page_size=page, physical_bytes=physical)
            quote = NATIVE.resource_quote_data(row, 4096, UPDATE)
            self.assertGreater(quote['requiredAvailableMemoryBytes'], (6 * 512 << 20) + (512 << 20) + (1 << 30))
            self.assertEqual(quote['maximumOriginals'], 96)
            quoted_disk = 2 * (quote['requiredAvailableDiskBytes'] - (3 << 30)) + (3 << 30)
            sample_memory = {'availableEstimateBytes': quote['requiredAvailableMemoryBytes']}
            self.assertEqual(NATIVE.resource_admission_data(sample_memory, quoted_disk, [quote, quote])['requiredAvailableDiskBytes'], quoted_disk)
            for mem, disk in (({'availableEstimateBytes': sample_memory['availableEstimateBytes'] - 1}, quoted_disk),
                              (sample_memory, quoted_disk - 1)):
                with self.assertRaises(NATIVE.Refused): NATIVE.resource_admission_data(mem, disk, [quote, quote])
            origin = NATIVE.Deadline(lambda: 20, started=10)
            self.assertEqual(origin.started, 10); self.assertEqual(origin.deadline, 600_000_000_010)
            for started in (0, 21, True):
                with self.assertRaises(NATIVE.Refused): NATIVE.Deadline(lambda: 20, started=started)
            now = [1]; deadline = NATIVE.Deadline(lambda: now[0])
            now[0] = deadline.work
            with self.assertRaises(NATIVE.Refused): deadline.check()
            deadline.finality = True; self.assertEqual(deadline.check(), now[0])
            now[0] = deadline.deadline
            with self.assertRaises(NATIVE.Refused): deadline.check()

            # Exercise the actual adapter control flow with finite filesystem
            # and original-command ports; never mount or execute any payload.
            uid, gid = os.getuid(), os.getgid()
            def info(dev, inode, mode, size=0):
                return SimpleNamespace(st_dev=dev, st_ino=inode, st_mode=mode, st_uid=uid, st_gid=gid,
                                       st_nlink=1, st_size=size, st_mtime_ns=1, st_ctime_ns=1)
            work = Path('/held/work')
            for fault in ('parser', 'unknown-attach', 'unknown-close', 'stale-restored'):
                fs = {work: info(1, 10, stat.S_IFDIR | 0o700)}; fdmap = {}; calls = []; books = []
                originals = fixture(target)[1]; image = b'inert image'
                class NativeBook(Book):
                    def __init__(self): super().__init__(); books.append(self)
                    def directory(self, path):
                        path = Path(path)
                        if path in self.directories: return self.directories[path]
                        if path != Path('/'): parent = self.directory(path.parent)
                        value = fs.setdefault(path, info(1, len(fs) + 20, stat.S_IFDIR | 0o700))
                        entry = {'path': path, 'kind': 'directory', 'fd': len(fdmap) + 1000,
                                 'closed': False, 'identity': NATIVE.identity(value)[:5]}
                        self.entries.append(entry); self.directories[path] = entry; fdmap[entry['fd']] = entry
                        return entry
                    def file(self, path, *args, **kwargs):
                        path = Path(path); self.directory(path.parent)
                        body = image if path.name.endswith('.dmg') else originals[path.name][0]
                        value = fs.setdefault(path, info(2 if path.parent.name.endswith('-mount') else 1,
                                                         len(fs) + 20, stat.S_IFREG | (0o444 if path.parent.name.endswith('-mount') else 0o600), len(body)))
                        entry = {'path': path, 'kind': 'file', 'fd': len(fdmap) + 1000, 'closed': False,
                                 'identity': NATIVE.identity(value), 'body': body}
                        self.entries.append(entry); fdmap[entry['fd']] = entry; return entry, body
                    def read(self, entry): return entry['body']
                    def finish(self):
                        result = super().finish()
                        if fault == 'unknown-close' and len(books) > 2 and self is books[2]: self.errors.append('unknown'); return False
                        return result
                s = NATIVE.Enrollment(Path('/source'), work, NATIVE.Deadline(lambda: 1), NativeBook)
                s.publish_image = lambda path, body: None  # Copy contract covered independently below.
                s.stager = SimpleNamespace(distribution_mount_data=lambda *args: '/dev/disk42s1')
                s.host = SimpleNamespace(filesystem=lambda fd: {'typeName': 'hfs', 'flags': 0x1001,
                                      'mountOn': str(work / 'arm64-mount'), 'mountFrom': '/dev/disk42s1'})
                def refused(*args): raise NATIVE.Refused('synthetic-parser-refusal')
                s.data = SimpleNamespace(mounted_data=refused if fault in ('parser', 'unknown-close') else lambda *args: ({}, b'x'))
                def command(role, argv, maximum, **kwargs):
                    calls.append((role, tuple(argv)))
                    if role == 'attach':
                        if fault == 'unknown-attach': raise NATIVE.Refused('synthetic-unknown-attach')
                        fs[work / 'arm64-mount'] = info(2, 30, stat.S_IFDIR | 0o700)
                    else: fs[work / 'arm64-mount'] = info(1, 999 if fault == 'stale-restored' else 11, stat.S_IFDIR | 0o700)
                    return SimpleNamespace(returncode=0, stdout=b'inert plist port', stderr=b'')
                s.command = command
                def mkdir(name, mode, *, dir_fd): fs[work / name] = info(1, 11, stat.S_IFDIR | mode)
                def stat_port(name, *, dir_fd=None, follow_symlinks=False):
                    path = Path(name) if dir_fd is None else fdmap[dir_fd]['path'] / name
                    if path not in fs and path.parent.name.endswith('-mount'):
                        body = originals[path.name][0]; fs[path] = info(2, len(fs) + 20, stat.S_IFREG | 0o444, len(body))
                    return fs[path]
                def list_port(fd):
                    path = fdmap[fd]['path']
                    return list(originals) if path.name.endswith('-mount') and fs[path].st_dev == 2 else []
                # Restore every ordinary API port before unittest can render
                # an unexpected error; source-file linecache reads remain real.
                with self.subTest(mountFault=fault), self.assertRaises(NATIVE.Refused):
                    with mock.patch.multiple(NATIVE.os, mkdir=mkdir, stat=stat_port,
                        fstat=lambda fd: fs[fdmap[fd]['path']], listdir=list_port,
                        fstatvfs=lambda fd: SimpleNamespace(f_flag=os.ST_RDONLY if fs[fdmap[fd]['path']].st_dev == 2 else 0),
                        rmdir=lambda name, dir_fd: fs.pop(work / name)), mock.patch.object(NATIVE.os.path, 'lexists', lambda path: Path(path) in fs):
                        s.inspect_image(image, row, target)
                roles = [role for role, _ in calls]
                self.assertEqual(roles, ['attach', 'detach'] if fault in ('parser', 'stale-restored') else ['attach'])
                if 'detach' in roles: self.assertEqual(calls[1][1], ('/usr/bin/hdiutil', 'detach', '/dev/disk42s1'))
                self.assertEqual(work / 'arm64-mount' in fs, fault != 'parser')
                if len(books) > 2:
                    self.assertTrue(all(entry['fd'] is None for entry in books[2].entries))

            # Real fixed-image publisher with ordinary syscall DATA ports;
            # quota is checked before open, short writes progress, close consumes.
            image = b'x' * 70000; calls = []; buffer = bytearray()
            class CopyBook(Book):
                def register(self, fd, path, kind):
                    entry = {'fd': fd, 'path': path, 'kind': kind, 'closed': False, 'identity': None}
                    self.entries.append(entry); return entry
                def read(self, entry): return bytes(buffer)
                def close(self, entry): calls.append('close'); entry['fd'] = None; entry['closed'] = True
            s = NATIVE.Enrollment(Path('/source'), work, clock, CopyBook)
            def open_port(name, flags, mode, *, dir_fd):
                self.assertEqual(s.quota.reserved, 4); calls.append('open'); return 7000
            def write_port(fd, view):
                count = min(4096, len(view)); buffer.extend(view[:count]); return count
            with mock.patch.multiple(NATIVE.os, open=open_port, write=write_port,
                    fchmod=lambda *a: None, fsync=lambda *a: None,
                    fstat=lambda fd: info(1, 123, stat.S_IFREG | 0o600, len(buffer))):
                s.publish_image(work / 'arm64.dmg', image)
            self.assertEqual(buffer, image); self.assertEqual(calls, ['open', 'close'])
            self.assertIsNone(s.outer.entries[-1]['fd']); self.assertTrue(s.outer.entries[-1]['closed'])
            prior = list(calls); s.quota.reserved = 96
            with self.assertRaises(NATIVE.Refused): s.publish_image(work / 'intel.dmg', image)
            self.assertEqual(calls, prior)
            with self.assertRaises(NATIVE.Refused): s.publish('bad.json', b'x' * (NATIVE.OUTPUT_LIMIT - NATIVE.TERMINAL_LIMIT + 1))
            # Persisted-output accounting and retirement never use a glob or
            # delete a changed/unrelated leaf, even after a known file close.
            for fault in ('none', 'private-changed', 'public-extra', 'public-changed', 'close-unknown'):
                s = NATIVE.Enrollment.__new__(NATIVE.Enrollment)
                s.work = work; s.clock = clock; s.point = lambda: None
                s.parent = {'fd': 7100}; outer = Book(); outer.entries = [{'kind': 'file', 'fd': 7200, 'closed': False}]
                public_dir = {'fd': 7101}; outer.directories = {work / 'public': public_dir}
                outer.close = lambda entry: (entry.update(fd=None, closed=True), outer.errors.append('unknown') if fault == 'close-unknown' else None)
                s.outer = outer; s.quota = SimpleNamespace(books=[outer])
                private_info = info(1, 200, stat.S_IFREG | 0o600, 1)
                public_infos = {name: info(1, 300 + i, stat.S_IFREG | 0o444, 1) for i, name in enumerate(NATIVE.PUBLIC_NAMES)}
                s.expected_public = NATIVE.PUBLIC_NAMES
                s.private = {'arm64-carrier.zip': NATIVE.identity(private_info)}
                s.public = {name: NATIVE.identity(value) for name, value in public_infos.items()}
                present, deleted = {'arm64-carrier.zip', 'public'}, []
                if fault == 'private-changed': private_info = info(1, 999, stat.S_IFREG | 0o600, 1)
                if fault == 'public-changed': public_infos[NATIVE.PUBLIC_NAMES[0]] = info(1, 999, stat.S_IFREG | 0o444, 1)
                def listed(fd): return list(present) if fd == 7100 else list(public_infos) + (['unrelated.json'] if fault == 'public-extra' else [])
                def statted(name, *, dir_fd, follow_symlinks): return private_info if dir_fd == 7100 else public_infos[name]
                def deleted_port(name, *, dir_fd): deleted.append(name); present.remove(name)
                with mock.patch.multiple(NATIVE.os, listdir=listed, stat=statted, unlink=deleted_port, fsync=lambda fd: None):
                    if fault == 'none': s.retire_private()
                    else:
                        with self.assertRaises(NATIVE.Refused): s.retire_private()
                self.assertEqual(deleted, ['arm64-carrier.zip'] if fault == 'none' else [])
                self.assertIsNone(outer.entries[0]['fd'])
            for error in (NATIVE.Refused('p0-task-deadline'), NATIVE.Refused('/private/path?sig=private'),
                          RuntimeError('Authorization: secret-value')):
                projection = NATIVE.failure_data(error); encoded = NATIVE.canonical(projection)
                self.assertIs(projection['nativeEnrollmentAccepted'], False)
                self.assertIs(projection['productReady'], False)
                self.assertNotIn(b'private/path', encoded); self.assertNotIn(b'secret-value', encoded)
                self.assertEqual(projection['condition'], 'p0-task-deadline' if error.args[0] == 'p0-task-deadline' else None)
                self.assertLess(len(encoded), NATIVE.TERMINAL_LIMIT)
        finally:
            NATIVE.STATE.clear(); NATIVE.STATE.update(old_state)
