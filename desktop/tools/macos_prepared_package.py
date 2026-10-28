"""Prepared signed input, never an installed candidate or renewed old custody.

Transport belongs to the standard workflow artifact actions. This module uses
existing package parsers and the existing operation custodian for fixed copies.
No generic archive extraction, network, signer or alternate Installer is added.
"""
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from types import MappingProxyType

MIB = 1024 * 1024
PACKAGE_LIMIT = 512 * MIB
RECEIPT_LIMIT = MANIFEST_LIMIT = 16384
ARTIFACT_LIMIT = 2 * PACKAGE_LIMIT + 128 * 1024
SCOPE = 'prepared-signed-input-not-installed'
WORKFLOW = '.github/workflows/desktop-macos-installed.yml'
REPOSITORY = 'Apdelrahman1911/mobile-release-kit'
BRANCH = 'verify/desktop-macos-candidate'
TARGETS = ('aarch64-apple-darwin', 'x86_64-apple-darwin')
FILES = {'MobileReleaseKit.pkg': PACKAGE_LIMIT, 'MobileReleaseKit-original.pkg': PACKAGE_LIMIT,
         'android-helper-finalize-package.json': RECEIPT_LIMIT, 'package-finalization.status': 2}
NAMES = frozenset((*FILES, 'PREPARED.json'))
PRODUCER_STEPS = (
    'Build fixed Installer presentation then sign and notarize the completed outer package before final P',
    'Publish only the prepared signed input checkpoint; not installed',
    'Retain prepared signed input for failed-job-only installation retries',
)
NATIVE_PRODUCER_STEPS = (
    'Sign and notarize the same completed observer package before final P',
    *PRODUCER_STEPS[1:],
)
NATIVE_HOSTS = {'tool-setup': 'macos-26', 'git-native': 'xcode-27'}
NATIVE_JOB_NAMES = {'tool-setup': 'Build signed candidate (Tool26)',
                    'git-native': 'Build signed candidate (Git27)'}
_SEAL = object()


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii') + b'\n'


def hex_data(value, size=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(size) + '}', value) is not None and value != '0' * size


def decimal(value):
    return type(value) is str and re.fullmatch('[1-9][0-9]{0,19}', value) is not None


def decode(body, limit):
    need(type(body) is bytes and 0 < len(body) <= limit, 'prepared-json-bound')
    def pairs(rows):
        need(len({key for key, _ in rows}) == len(rows), 'prepared-json-duplicate')
        return dict(rows)
    def constant(_):
        raise ValueError('prepared-json-constant')
    return json.loads(body, object_pairs_hook=pairs, parse_constant=constant)


def origin_data(value):
    ordinary = {'source', 'tree', 'target', 'runId', 'runAttempt', 'jobId'}
    native = type(value) is dict and set(value) == ordinary | {'nativeScope', 'hostProfile'}
    need(type(value) is dict and (set(value) == ordinary or native)
         and all(hex_data(value[k], 40) for k in ('source', 'tree')) and value['target'] in TARGETS
         and all(decimal(value[k]) for k in ('runId', 'runAttempt', 'jobId')), 'prepared-origin')
    if native:
        need(value['target'] == TARGETS[0] and type(value['nativeScope']) is str and value['nativeScope'] in NATIVE_HOSTS
             and value['hostProfile'] == NATIVE_HOSTS[value['nativeScope']], 'prepared-native-origin')
    return dict(value)


def artifact_name(origin):
    origin = origin_data(origin)
    if 'nativeScope' in origin:
        return 'macos-candidate-package-' + origin['nativeScope'] + '-' + origin['source'] + '-' + origin['runId'] + '-' + origin['runAttempt']
    return 'mobile-release-kit-macos26-' + origin['target'] + '-prepared-' + origin['source'] + '-' + origin['runId'] + '-' + origin['runAttempt']


def manifest_data(value):
    fields = {'schemaVersion', 'scope', 'origin', 'packageRole', 'packageVersion', 'release',
              'packagerUid', 'packagerGid', 'inventorySha256', 'runtimeManifestSha256', 'members',
              'originalFinalizationReturnedZero', 'originalClosesKnown', 'installed', 'productReady', 'normalBuild'}
    native = type(value) is dict and value.get('schemaVersion') == 2
    if native:
        fields = fields - {'normalBuild'} | {'observerBuild'}
    need(type(value) is dict and set(value) == fields and type(value['schemaVersion']) is int
         and value['schemaVersion'] == (2 if native else 1) and value['scope'] == SCOPE
         and value['packageRole'] == ('installed-shell-observation' if native else 'ordinary-image')
         and value['originalFinalizationReturnedZero'] is value['originalClosesKnown'] is True
         and value['installed'] is value['productReady'] is False, 'prepared-manifest')
    origin_data(value['origin'])
    need(('nativeScope' in value['origin']) is native, 'prepared-origin-role')
    build = value['observerBuild'] if native else value['normalBuild']
    build_keys = ({'appBinarySha256BeforeSigning', 'entryBinarySha256BeforeSigning'} if native
                  else {'appBinarySha256BeforeSigning', 'desktopImageSha256BeforeSigning'})
    need(type(build) is dict and set(build) == build_keys
         and all(hex_data(v) for v in build.values()), 'prepared-original-build')
    need(all(type(value[k]) is int and 0 <= value[k] < 2**32 for k in ('packagerUid', 'packagerGid'))
         and value['packagerUid'] != 0 and all(hex_data(value[k]) for k in ('inventorySha256', 'runtimeManifestSha256'))
         and type(value['release']) is str and re.fullmatch('[a-z0-9_.-]{1,63}', value['release'])
         and type(value['packageVersion']) is str and re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}', value['packageVersion']),
         'prepared-package-binding')
    rows = value['members']
    need(type(rows) is list and len(rows) == len(FILES), 'prepared-member-count')
    for row, name in zip(rows, sorted(FILES)):
        need(type(row) is dict and set(row) == {'name', 'bytes', 'sha256'} and row['name'] == name
             and type(row['bytes']) is int and 0 < row['bytes'] <= FILES[name] and hex_data(row['sha256']),
             'prepared-member-binding')
    need(next(row for row in rows if row['name'] == 'package-finalization.status') ==
         {'name': 'package-finalization.status', 'bytes': 2, 'sha256': sha(b'0\n')}, 'prepared-caller-status')
    need(len(canonical(value)) <= MANIFEST_LIMIT, 'prepared-manifest-bound')
    return value


def producer_steps_data(job, *, native=False):
    required = NATIVE_PRODUCER_STEPS if native else PRODUCER_STEPS
    steps = job.get('steps')
    need(type(steps) is list and len(required) <= len(steps) <= 256
         and all(type(row) is dict and type(row.get('number')) is int and 0 < row['number'] <= 256 for row in steps)
         and len({row['number'] for row in steps}) == len(steps), 'prepared-service-steps')
    previous = 0
    for name in required:
        rows = [row for row in steps if row.get('name') == name]
        need(len(rows) == 1 and rows[0].get('status') == 'completed' and rows[0].get('conclusion') == 'success'
             and rows[0]['number'] > previous, 'prepared-service-cut')
        previous = rows[0]['number']


def metadata_data(run, job, artifact, manifest):
    """Authenticate exact closed cut; whole-job success is not its substitute."""
    origin = manifest_data(manifest)['origin']
    native_scope = origin.get('nativeScope')
    need(type(run) is type(job) is type(artifact) is dict, 'prepared-service-shape')
    need(all(type(run.get(k)) is int and run[k] == int(origin[v]) for k, v in (('id', 'runId'), ('run_attempt', 'runAttempt')))
         and run.get('head_sha') == origin['source'] and run.get('head_branch') == BRANCH and run.get('event') == 'push'
         and run.get('path') == WORKFLOW and type(run.get('workflow_id')) is int and run['workflow_id'] == 363563168
         and type(run.get('repository')) is dict
         and run['repository'].get('full_name') == REPOSITORY, 'prepared-service-run')
    need(all(type(job.get(k)) is int and job[k] == int(origin[v]) for k, v in (('id', 'jobId'), ('run_id', 'runId'), ('run_attempt', 'runAttempt')))
         and job.get('head_sha') == origin['source']
         and job.get('name') == (NATIVE_JOB_NAMES[native_scope] if native_scope else 'normal-installed-' + origin['target']),
         'prepared-service-job')
    producer_steps_data(job, native=native_scope is not None)
    producer = artifact.get('workflow_run')
    need(type(artifact.get('id')) is int and artifact['id'] > 0 and artifact.get('name') == artifact_name(origin)
         and artifact.get('expired') is False and type(artifact.get('size_in_bytes')) is int
         and 22 <= artifact['size_in_bytes'] <= ARTIFACT_LIMIT and type(artifact.get('digest')) is str
         and artifact['digest'].startswith('sha256:') and hex_data(artifact['digest'][7:])
         and type(producer) is dict and type(producer.get('id')) is int and producer['id'] == int(origin['runId'])
         and producer.get('head_sha') == origin['source'] and producer.get('head_branch') == BRANCH,
         'prepared-service-artifact')
    return {'artifactId': str(artifact['id']), 'artifactBytes': artifact['size_in_bytes'],
            'artifactSha256': artifact['digest'][7:], 'origin': dict(origin)}


def cohort_data(values):
    need(type(values) is dict and set(values) == NAMES, 'prepared-cohort-roster')
    manifest = manifest_data(decode(values['PREPARED.json'], MANIFEST_LIMIT))
    for row in manifest['members']:
        body = values[row['name']]
        need(type(body) is bytes and len(body) == row['bytes'] and sha(body) == row['sha256'], 'prepared-cohort-bytes')
    need(values['package-finalization.status'] == b'0\n', 'prepared-cohort-status')
    return manifest


LOCAL_CARRIER_FILES = {
    'producer-root/producer.json': 65536,
    'producer-root/producer.sig': 512,
    'prepared-input/PREPARED.json': MANIFEST_LIMIT,
    'android-helper-package-install.json': 4 * MIB,
    'package-install.status': 2,
}


def local_carrier_transport_data(values, consumer):
    """Correlate already signed output DATA; grant no local/native authority."""
    from desktop.tools import stage_macos_installed as stager
    need(type(values) is dict and set(values) == set(LOCAL_CARRIER_FILES)
         and all(type(values[n]) is bytes and 0 < len(values[n]) <= limit
                 for n, limit in LOCAL_CARRIER_FILES.items()), 'local-carrier-roster')
    need(values['package-install.status'] == b'0\n', 'local-carrier-original-status')
    manifest = manifest_data(decode(values['prepared-input/PREPARED.json'], MANIFEST_LIMIT))
    need(manifest['origin'].get('nativeScope') == 'tool-setup'
         and manifest['origin'].get('hostProfile') == 'macos-26', 'local-carrier-tool-source')
    need(type(consumer) is dict and set(consumer) == {
        'source', 'tree', 'target', 'runId', 'runAttempt', 'nativeScope', 'hostProfile'}
         and all(hex_data(consumer[k], 40) for k in ('source', 'tree'))
         and all(decimal(consumer[k]) for k in ('runId', 'runAttempt'))
         and consumer['target'] == manifest['origin']['target']
         and (consumer['source'] != manifest['origin']['source'] or consumer['tree'] == manifest['origin']['tree'])
         and consumer['nativeScope'] == 'tool-setup' and consumer['hostProfile'] == 'macos-26',
         'local-carrier-consumer')
    descriptor, signed = values['producer-root/producer.json'], values['producer-root/producer.sig']
    current = stager.maintenance_producer_data(descriptor, target=consumer['target'])['releaseSet']['current']
    package = next(row for row in manifest['members'] if row['name'] == 'MobileReleaseKit.pkg')
    for key, expected in {'sourceCommit': manifest['origin']['source'], 'packageSha256': package['sha256'],
            'inventorySha256': manifest['inventorySha256'], 'runtimeManifestSha256': manifest['runtimeManifestSha256'],
            'release': manifest['release'], 'packageVersion': manifest['packageVersion']}.items():
        need(current[key] == expected, 'local-carrier-package-binding')
    receipt = decode(values['android-helper-package-install.json'], 4 * MIB)
    need(type(receipt) is dict and all(k in receipt and type(receipt[k]) is type(v) and receipt[k] == v for k, v in {
        'schemaVersion': 1, 'phase': 'package-install', 'target': consumer['target'],
        'source': consumer['source'], 'workflowSource': consumer['source'],
        'runId': consumer['runId'], 'runAttempt': consumer['runAttempt'],
        'packageRole': 'installed-shell-observation', 'passed': True,
        'originalClosesKnown': True, 'targetRetired': True,
        'directStagerIOPending': None, 'cleanupErrors': []}.items()), 'local-carrier-owner')
    calls = receipt.get('originalCalls')
    need(type(calls) is list and len(calls) == len(stager.PACKAGING_CALL_ROLES), 'local-carrier-owner-calls')
    for call, role in zip(calls, stager.PACKAGING_CALL_ROLES):
        need(type(call) is dict and call.get('role') == role
             and all(call.get(k) is True for k in ('entered', 'returned', 'capturesSettled'))
             and type(call.get('returncode')) is int
             and all(hex_data(call.get(k)) for k in ('stdoutSha256', 'stderrSha256'))
             and call['returncode'] in ((0, 1) if role in ('installer-log-cursor', 'installer-log-capture') else (0,)),
             'local-carrier-owner-calls')
    distribution = receipt.get('distribution')
    need(type(distribution) is dict and all(k in distribution and type(distribution[k]) is type(v) and distribution[k] == v for k, v in {
        'packageSha256': package['sha256'], 'packageBytes': package['bytes'],
        'descriptorSha256': sha(descriptor), 'signatureSha256': sha(signed),
        'originalInstallerReturnedZero': True, 'sameRequestV2Readback': True,
        'originalMountDetached': True, 'groupEndpointMet': True}.items()), 'local-carrier-distribution')
    summary = distribution.get('producerSummary')
    need(type(summary) is dict and all(type(summary.get(k)) is int for k in ('schemaVersion', 'descriptorBytes', 'signatureBytes'))
         and summary == {
        'schemaVersion': 1, 'kind': 'mrk-package-producer-emitted',
        'packageSha256': package['sha256'], 'descriptorSha256': sha(descriptor),
        'signatureSha256': sha(signed), 'descriptorBytes': len(descriptor), 'signatureBytes': len(signed)},
        'local-carrier-emission')
    return {'schemaVersion': 1, 'scope': 'authenticated-package-transport-not-local-installation',
            'producer': dict(manifest['origin']), 'consumer': dict(consumer),
            'packageSha256': package['sha256'], 'packageBytes': package['bytes'],
            'inventorySha256': manifest['inventorySha256'], 'runtimeManifestSha256': manifest['runtimeManifestSha256'],
            'members': [{'name': n, 'bytes': len(values[n]), 'sha256': sha(values[n])} for n in sorted(values)],
            'originalPackageOwnerReturnedZero': True, 'originalClosesKnown': True,
            'independentDownloadedSignatureVerificationRequired': True,
            'independentSourceAndAttemptVerificationRequired': True,
            'localInstallationQualified': False, 'localServiceQualified': False,
            'allElevenGroupsQualified': False}


HARNESS_FILES = frozenset({
    '.github/workflows/desktop-macos-installed.yml',
    '.github/workflows/desktop-macos-candidate-tests.yml', '.github/actionlint.yaml',
    'desktop/tools/macos_prepared_package.py', 'desktop/tools/macos_android_helper_package.py',
    'desktop/tools/macos_identity_current_runtime.py', 'desktop/tools/macos_aqua_qualification.py',
    'desktop/tools/macos_tool_setup_inputs.py', 'desktop/tools/macos_local_preflight.py',
    'desktop/tools/macos_tool_service_diagnostic.py',
    'tests/desktop/test_macos_candidate_stages.py', 'tests/desktop/test_macos_prepared_package.py',
    'tests/desktop/test_macos_distribution_detach.py',
    'MACOS-CONTINUATION.md', 'MACOS-LOCAL-RESULTS.md', 'docs/macos-ci-retries.md',
})


def compatible_harness_data(value, origin, consumer):
    """Complete GitHub comparison, confined to test/packaging orchestration.

    Application, native, runtime, compiler inputs, profiles and pins cannot
    change. The original checkout still supplies the package producer build.
    Compare responses contain at most300 files: strictly fewer proves that
    this first page is complete. The commit list must also be complete.
    """
    need(type(value) is dict and value.get('status') == 'ahead'
         and value.get('behind_by') == 0 and type(value.get('total_commits')) is int
         and 0 < value['total_commits'] <= 50 and value.get('ahead_by') == value['total_commits'],
         'prepared-harness-history')
    need(value.get('base_commit', {}).get('sha') == origin['source']
         and value.get('merge_base_commit', {}).get('sha') == origin['source'], 'prepared-harness-ancestor')
    commits = value.get('commits')
    need(type(commits) is list and len(commits) == value['total_commits']
         and commits[-1].get('sha') == consumer['source']
         and commits[-1].get('commit', {}).get('tree', {}).get('sha') == consumer['tree']
         and value['base_commit'].get('commit', {}).get('tree', {}).get('sha') == origin['tree'],
         'prepared-harness-source-tree')
    rows = value.get('files')
    need(type(rows) is list and 0 < len(rows) < 300
         and all(type(row) is dict and row.get('filename') in HARNESS_FILES
                 and row.get('status') in ('added', 'modified', 'removed')
                 and 'previous_filename' not in row for row in rows)
         and len({row['filename'] for row in rows}) == len(rows), 'prepared-harness-files')
    return True


class PreparedBinding:
    """Private admitted provenance, never old live-custody or a caller flag."""
    __slots__ = ('_manifest', '_consumer', '_artifact', '_compatible')

    def __init__(self, seal, manifest, consumer, artifact, compatible=False):
        need(seal is _SEAL, 'prepared-binding-constructor')
        self._manifest = canonical(manifest)
        self._consumer = MappingProxyType(dict(consumer))
        self._artifact = MappingProxyType(dict(artifact))
        self._compatible = compatible

    @property
    def manifest(self):
        return decode(self._manifest, MANIFEST_LIMIT)

    @property
    def origin(self):
        return self.manifest['origin']

    @property
    def source(self):
        return self.origin['source']

    @property
    def same_source(self):
        return self.source == self._consumer['source']

    @property
    def native_compatible(self):
        return self.same_source or self._compatible is True

    @property
    def consumer(self):
        return dict(self._consumer)

    def preview_inputs(self, stager, args):
        need(self.same_source and args.candidate_carrier is True and args.expected_source == self.source
             and args.target == self.origin['target'], 'prepared-candidate-same-source-only')
        self.finalization_environment(os.environ)
        m = self.manifest
        binding = dict(source=self.source, tree=self._consumer['tree'], runId=self._consumer['runId'],
                       runAttempt=self._consumer['runAttempt'], runtimeManifestSha256=m['runtimeManifestSha256'])
        inventory = stager.observation_inventory_bytes(stager.read(Path(args.work) / 'input/install-inventory.json', stager.INVENTORY_BYTES),
            m['inventorySha256'], m['runtimeManifestSha256'], selection=stager.source_build_selection(args.target))
        app = dict(m['normalBuild'], residentImageSha256=inventory['app/' + stager.RESIDENT_IMAGE]['sha256'],
                   androidHelperSha256=inventory['app/' + stager.ANDROID_HELPER]['sha256'])
        normal = {'binarySha256': m['normalBuild']['desktopImageSha256BeforeSigning']}
        return binding, {'source': self.source, 'tree': self._consumer['tree']}, app, normal

    def finalization_environment(self, environment):
        need(environment['GITHUB_SHA'] == self._consumer['source']
             and environment['GITHUB_RUN_ID'] == self._consumer['runId']
             and environment['GITHUB_RUN_ATTEMPT'] == self._consumer['runAttempt'], 'prepared-current-consumer')
        old = self.origin
        # DATA argument for the old receipt parser ONLY, NEVER a process env.
        return {**environment, 'GITHUB_SHA': old['source'], 'GITHUB_WORKFLOW_SHA': old['source'],
                'GITHUB_RUN_ID': old['runId'], 'GITHUB_RUN_ATTEMPT': old['runAttempt'],
                'GITHUB_WORKFLOW_REF': REPOSITORY + '/' + WORKFLOW + '@refs/heads/' + BRANCH,
                'MRK_MACOS_INSTALL_SOURCE_COMMIT': old['source']}


def native_origin(environment):
    scope = environment.get('MRK_MACOS_NATIVE_SCOPE', 'disabled')
    if scope == 'disabled':
        return {}
    need(type(scope) is str and scope in NATIVE_HOSTS
         and environment.get('MRK_MACOS_RUNNER') == NATIVE_HOSTS[scope]
         and environment.get('MRK_MACOS_PACKAGE_ROLE') == 'installed-shell-observation', 'prepared-native-selection')
    return dict(nativeScope=scope, hostProfile=NATIVE_HOSTS[scope])


def consumer_data(environment, tree, target):
    return dict(source=environment['GITHUB_SHA'], tree=tree, target=target,
        runId=environment['GITHUB_RUN_ID'], runAttempt=environment['GITHUB_RUN_ATTEMPT'], **native_origin(environment))


def admit_data(values, service, consumer):
    manifest = cohort_data(values)
    need(type(service) is dict and set(service) in ({'run', 'job', 'artifact'},
         {'run', 'job', 'artifact', 'compatibility'}), 'prepared-service-records')
    artifact = metadata_data(service['run'], service['job'], service['artifact'], manifest)
    native = {k: manifest['origin'][k] for k in ('nativeScope', 'hostProfile') if k in manifest['origin']}
    need(type(consumer) is dict and set(consumer) == {'source', 'tree', 'target', 'runId', 'runAttempt'} | set(native)
         and all(consumer[k] == v for k, v in native.items())
         and all(hex_data(consumer[k], 40) for k in ('source', 'tree'))
         and all(decimal(consumer[k]) for k in ('runId', 'runAttempt'))
         and consumer['target'] == manifest['origin']['target']
         and (consumer['source'] != manifest['origin']['source'] or consumer['tree'] == manifest['origin']['tree']), 'prepared-consumer')
    compatible = False
    if native and consumer['source'] != manifest['origin']['source']:
        compatible = compatible_harness_data(service.get('compatibility'), manifest['origin'], consumer)
    elif 'compatibility' in service:
        need(consumer['source'] != manifest['origin']['source'], 'prepared-harness-unnecessary')
    return PreparedBinding(_SEAL, manifest, consumer, artifact, compatible)


def quote_data(package_bytes, original_bytes, expanded_bytes, inventory_bytes):
    need(all(type(n) is int for n in (package_bytes, original_bytes, expanded_bytes, inventory_bytes))
         and all(0 < n <= PACKAGE_LIMIT for n in (package_bytes, original_bytes, expanded_bytes))
         and 0 < inventory_bytes <= 12 * MIB, 'prepared-resource-values')
    # Full overlapping DATA/copy peak, not only logical payload bytes. Later
    # package-owner images require separate admission after these vectors drop.
    return {'memoryBytes': 3 * (package_bytes + original_bytes) + 4 * expanded_bytes + 2 * inventory_bytes + 32 * MIB,
            'diskBytes': 2 * (package_bytes + original_bytes) + expanded_bytes + inventory_bytes + 32 * MIB}


def gzip_expansion_bytes(body, *, check=lambda: None, limit=PACKAGE_LIMIT):
    """Count a single gzip stream with64KiB input/output windows, never retain it."""
    import zlib
    stream = zlib.decompressobj(31)
    total = 0
    for offset in range(0, len(body), 65536):
        check()
        pending = body[offset:offset + 65536]
        while pending:
            output = stream.decompress(pending, 65536)
            total += len(output)
            need(total <= limit and not stream.unused_data, 'prepared-streamed-expansion-bound')
            pending = stream.unconsumed_tail
    need(stream.eof and not stream.unused_data and not stream.unconsumed_tail and 0 < total <= limit,
         'prepared-streamed-expansion-complete')
    return total


def original_expansion_bytes(stager, original, *, check=lambda: None):
    """Small XAR index + streaming census before any full Scripts allocation.

    This chooses a resource quote only. The unchanged full XAR/CPIO/package
    parsers still validate every byte. Other valid XAR encodings retain the
    conservative maximum rather than guessing their nested expansion size.
    """
    import struct
    import xml.etree.ElementTree as ET
    need(type(original) is bytes and 28 <= len(original) <= PACKAGE_LIMIT, 'prepared-expansion-header')
    magic, header, version, compressed, expanded, _ = struct.unpack_from('>IHHQQI', original)
    need(magic == 0x78617221 and header == 28 and version == 1
         and 0 < compressed <= MIB and 0 < expanded <= 2 * MIB
         and header + compressed <= len(original), 'prepared-expansion-header')
    body = stager.inflate(original[header:header + compressed], expanded)
    need(len(body) == expanded and b'<!DOCTYPE' not in body.upper() and b'<!ENTITY' not in body.upper(),
         'prepared-expansion-index')
    root = ET.fromstring(body)
    rows = root.findall('toc/file')
    need(root.tag == 'xar' and len(root.findall('toc')) == 1 and len(rows) == 2
         and {r.findtext('name') for r in rows} == {'PackageInfo', 'Scripts'}, 'prepared-expansion-index')
    row = next(r for r in rows if r.findtext('name') == 'Scripts')
    fields = [row.findtext('data/' + k) for k in ('offset', 'length', 'size')]
    need(all(type(v) is str and re.fullmatch(r'[0-9]{1,10}', v) for v in fields), 'prepared-expansion-index')
    offset, length, size = map(int, fields)
    start = header + compressed + offset
    need(0 < length <= PACKAGE_LIMIT and 0 < size <= PACKAGE_LIMIT and start + length <= len(original)
         and row.findtext('type') == 'file' and not row.findall('file'), 'prepared-expansion-index')
    encoding = row.find('data/encoding')
    need(encoding is not None and encoding.get('style') in ('application/octet-stream', 'application/x-gzip'),
         'prepared-expansion-index')
    if encoding.get('style') != 'application/octet-stream':
        return PACKAGE_LIMIT
    need(length == size, 'prepared-expansion-index')
    view = memoryview(original)[start:start + length]
    if view[:2] == b'\x1f\x8b':
        return gzip_expansion_bytes(view, check=check)
    return size


def original_scripts_data(stager, original, manifest, *, allocation_budget=None, expanded_limit=PACKAGE_LIMIT):
    manifest_data(manifest)
    need(stager.packager_ids() == (manifest['packagerUid'], manifest['packagerGid']), 'prepared-packager-identity')
    members = stager.xar_members(original, allocation_budget=allocation_budget)
    need(set(members) == {'PackageInfo', 'Scripts'}, 'prepared-original-roster')
    selection = stager.BuildSelection(manifest['origin']['target'], manifest['packageVersion'], manifest['release'])
    stager.package_info(members['PackageInfo'], selection=selection)
    body = members['Scripts']
    if body[:2] == b'\x1f\x8b':
        if allocation_budget is not None:
            allocation_budget('scripts-inflate', len(original) + sum(map(len, members.values())), len(body), expanded_limit)
        body = stager.inflate(body, expanded_limit, gzip=True)
    need(0 < len(body) <= expanded_limit <= PACKAGE_LIMIT, 'prepared-expansion-correspondence')
    rows = stager._cpio_members(body, stager.packager_ids(), allocation_budget=allocation_budget, store_runtime=True)
    files = {name: value for name, value in rows.items() if value[0] is not None}
    need(rows == {**files, **{name: (None, 0o555) for name in stager.directories(files, mac_store_prefix='input/runtime/store')}},
         'prepared-original-directory-census')
    need(0 < len(files) <= stager.MAX_FILES and sum(len(v[0]) for v in files.values()) <= stager.MAX_BYTES,
         'prepared-original-file-bound')
    inventory = files.get('input/' + stager.INSTALLATION_INVENTORY_NAME)
    need(type(inventory) is tuple and inventory[1] == 0o444
         and sha(inventory[0]) == manifest['inventorySha256'], 'prepared-original-inventory')
    stager.observation_inventory_bytes(inventory[0], manifest['inventorySha256'], manifest['runtimeManifestSha256'], selection=selection)
    return files


def initialize_staging(op):
    """Existing original owner, no command or credential call in this phase."""
    import time
    need(op.phase == 'package-install' and not op.calls and not op.entries, 'prepared-staging-owner')
    op.prepared_staging = True
    op.open()
    source_head(op, op.prepared_binding.source if op.prepared_binding is not None else op.environment['GITHUB_SHA'])
    op.package_started = op.package_observed = time.monotonic_ns()
    op.package_endpoint = op.package_started + 180_000_000_000
    op.profile_entry = op.source_original('desktop/packaging/macos-android-service-signing.profile', 'source-signing-profile', 1024)
    op.service_profile = op.read(op.profile_entry)
    op.signing = op.stager.service_signing_data(op.service_profile)
    op.producer_profile_entry = op.source_original('desktop/packaging/macos-install-producer-signing.profile', 'source-producer-profile', 1024)
    op.producer_profile = op.read(op.producer_profile_entry)
    op.stager.packaging_signing_data(op.producer_profile, op.service_profile)
    op.package_sources.extend(((op.profile_entry, op.service_profile), (op.producer_profile_entry, op.producer_profile)))
    release = op.image_binding()
    op.package_sources.append((op.release_entry, release))
    need(op.selected_package_store() is True, 'prepared-fixed-store-profile')


def finish_staging(op, primary=None):
    try:
        op.finish()
        need(len(op.calls) <= 16 and all(row.get('role') == 'prepared-resource-memory'
             and row.get('entered') is row.get('returned') is row.get('capturesSettled') is True
             and type(row.get('returncode')) is int and row['returncode'] == 0 for row in op.calls)
             and not op.credential_calls and not op.credential_contexts and not op.errors
             and op.receipt.get('originalClosesKnown') is True and op.receipt.get('targetRetired') is True
             and all(entry['closed'] and entry['fd'] is None for entry in op.entries), 'prepared-staging-original-closes')
    except BaseException:
        if primary is None:
            raise
        BaseException.add_note(primary, 'prepared-staging-original-closes')


def export_checkpoint(op, origin):
    """Actual closed finalization+original files -> five fixed fresh copies."""
    from types import SimpleNamespace
    origin = origin_data(origin)
    need(op.prepared_binding is None and origin['source'] == op.environment['GITHUB_SHA']
         and (origin['target'], origin['runId'], origin['runAttempt']) ==
             (op.target, op.environment['GITHUB_RUN_ID'], op.environment['GITHUB_RUN_ATTEMPT']), 'prepared-export-origin')
    completed = False
    try:
        initialize_staging(op)
        final_root = op.directory(op.work_entry, 'package-final', 'prepared-final-root')
        final = op.original(final_root, 'MobileReleaseKit.pkg', 'prepared-final', PACKAGE_LIMIT, (0o444,))
        original = op.original(op.work_entry, 'MobileReleaseKit-original.pkg', 'prepared-original-package', PACKAGE_LIMIT, (0o400, 0o444, 0o600, 0o644))
        guard = ResourceGuard(op)
        guard.check(quote_data(final['identity'][6], original['identity'][6], PACKAGE_LIMIT, 12 * MIB))
        package = op.read(final)
        record = op.package_finalization_input(final, package)
        args = SimpleNamespace(target=op.target, fixture=False, store_runtime=True,
            scripts=op.work / 'scripts', package=op.work / 'package-final/MobileReleaseKit.pkg',
            original_package=op.work / 'MobileReleaseKit-original.pkg')
        audit = op.package_stager_io('final-audit', args)
        need(audit['packageSha256'] == sha(package) and audit['packageSize'] == len(package)
             and all(audit[k] == record[k] for k in ('originalPackageSha256', 'packageInfoSha256', 'scriptFileCount')),
             'prepared-export-audit')
        old = op.read(original)
        need(sha(old) == record['originalPackageSha256'], 'prepared-export-original-package')
        values = {'MobileReleaseKit.pkg': package, 'MobileReleaseKit-original.pkg': old}
        for name in ('android-helper-finalize-package.json', 'package-finalization.status'):
            entry = op.original(op.work_entry, name, 'prepared-' + name, FILES[name], (0o400, 0o444, 0o600, 0o644))
            values[name] = op.read(entry)
            op.package_outputs.append((entry, sha(values[name])))
        need(values['package-finalization.status'] == b'0\n', 'prepared-export-caller-zero')
        op.package_outputs.extend(((final, sha(package)), (original, sha(old))))
        selection = op.stager.build_release_data(op.read(op.release_entry), target=op.target)
        normal = original_build_facts(op, origin, package_version=selection['packageVersion'])
        native = 'nativeScope' in origin
        manifest = dict(schemaVersion=2 if native else 1, scope=SCOPE, origin=origin,
            packageRole='installed-shell-observation' if native else 'ordinary-image',
            packageVersion=selection['packageVersion'], release=selection['release'],
            packagerUid=os.getuid(), packagerGid=os.getgid(),
            inventorySha256=op.environment['MRK_MACOS_INSTALL_INVENTORY_SHA256'],
            runtimeManifestSha256=op.environment['MRK_BUNDLED_RUNTIME_MANIFEST_SHA256'],
            members=[{'name': name, 'bytes': len(values[name]), 'sha256': sha(values[name])} for name in sorted(FILES)],
            originalFinalizationReturnedZero=True, originalClosesKnown=True, installed=False, productReady=False,
            **{'observerBuild' if native else 'normalBuild': normal})
        manifest_data(manifest)
        # Bind the manifest's inventory/runtime anchors to the same original
        # package, before publishing a checkpoint, not only on its consumer.
        original_scripts_data(op.stager, old, manifest, allocation_budget=guard.allocation)
        root = op.package_directory('prepared')
        for name in sorted(FILES):
            op.package_file(root, name, values[name])
        # Provisional until all same-owner POST/consuming closes and caller0.
        op.package_file(root, 'PREPARED.json', canonical(manifest))
        op.package_roots.append((root, set(NAMES)))
        op.package_post()
        completed = True
    finally:
        finish_staging(op, sys.exception())
    need(completed, 'prepared-export-incomplete')
    return manifest


def hydrate_checkpoint(op, values, binding):
    """Fresh current copies; no old status/FD or compiler output is adopted."""
    from types import SimpleNamespace
    need(type(binding) is PreparedBinding and op.prepared_binding is binding
         and cohort_data(values) == binding.manifest, 'prepared-hydration-binding')
    manifest = binding.manifest
    completed = False
    try:
        initialize_staging(op)
        guard = ResourceGuard(op)
        package_size, original_size = len(values['MobileReleaseKit.pkg']), len(values['MobileReleaseKit-original.pkg'])
        # First admit only the retained packages plus the small bounded index/
        # streaming windows. Count expansion before allocating its full vector.
        guard.check(quote_data(package_size, original_size, 1, 1))
        # Publish and positively read back the already admitted final package
        # before retaining expanded Scripts. package_file keeps its original
        # and digest, not this whole byte vector. Consume the vector only after
        # that write/readback returns; the full allocation quote stays unchanged.
        root = op.package_directory('package-final')
        op.package_file(root, 'MobileReleaseKit.pkg', values['MobileReleaseKit.pkg'])
        del values['MobileReleaseKit.pkg']
        expanded = original_expansion_bytes(op.stager, values['MobileReleaseKit-original.pkg'], check=op.package_clock)
        quote = quote_data(package_size, original_size, expanded, 12 * MIB)
        # Acquire a NEW original from the unchanged complete transport cohort.
        # Its earlier acquisition already consumed every handle. Retain only
        # this fresh FD and expected digest, not the old full byte vector, while
        # admitting the complete peak before allocating its replacement.
        transport = op.directory(op.work_entry, 'prepared-input', 'prepared-reopened-root')
        need(set(os.listdir(transport['fd'])) == NAMES, 'prepared-transport-original-roster')
        source_original = op.original(transport, 'MobileReleaseKit-original.pkg', 'prepared-reopened-package-original',
                                      PACKAGE_LIMIT, (0o400, 0o444, 0o600, 0o644))
        original_sha = next(row['sha256'] for row in manifest['members'] if row['name'] == 'MobileReleaseKit-original.pkg')
        need(source_original['identity'][6] == original_size, 'prepared-member-original-size')
        op.package_outputs.append((source_original, original_sha))
        op.package_roots.append((transport, NAMES))
        del values['MobileReleaseKit-original.pkg']
        guard.check(quote)
        original_body = op.read(source_original)
        need(len(original_body) == original_size and sha(original_body) == original_sha, 'prepared-hydrated-audit')
        files = original_scripts_data(op.stager, original_body, manifest,
                                      allocation_budget=guard.allocation, expanded_limit=expanded)
        inventory = files['input/' + op.stager.INSTALLATION_INVENTORY_NAME][0]
        # Existing finite writer performs positive leaf closes and full readback;
        # exceptions remain pending, so no later owner may accept these copies.
        op.stager_io_pending = 'prepared-scripts'
        op.stager.write_tree(op.work / 'scripts', files, root_mode=0o755, mac_store_prefix='input/runtime/store')
        op.stager_io_pending = None
        # The independent full audit rereads the fresh tree. Retaining this
        # extra whole-payload dictionary would overlap another501MiB with it.
        del files
        op.package_file(op.work_entry, 'MobileReleaseKit-original.pkg', original_body)
        del original_body
        for name in ('android-helper-finalize-package.json', 'package-finalization.status'):
            op.publish(name, values[name])  # Fresh600 original, not old mode/custody.
        input_root = op.package_directory('input')
        op.package_file(input_root, op.stager.INSTALLATION_INVENTORY_NAME, inventory)
        # Admit the same complete quote again before the independent rereads.
        # Neither retained package vector overlaps this later full DATA audit.
        guard.check(quote)
        original = op.original(root, 'MobileReleaseKit.pkg', 'prepared-hydrated-final', PACKAGE_LIMIT, (0o444,))
        package = op.read(original)
        need(len(package) == package_size and sha(package) == next(
            row['sha256'] for row in manifest['members'] if row['name'] == 'MobileReleaseKit.pkg'),
            'prepared-hydrated-audit')
        record = op.package_finalization_input(original, package)
        del package
        audit = op.package_stager_io('final-audit', SimpleNamespace(target=op.target, fixture=False, store_runtime=True,
            scripts=op.work / 'scripts', package=op.work / 'package-final/MobileReleaseKit.pkg',
            original_package=op.work / 'MobileReleaseKit-original.pkg'))
        need(audit['packageSha256'] == record['packageSha256']
             and all(audit[k] == record[k] for k in ('originalPackageSha256', 'packageInfoSha256', 'scriptFileCount')),
             'prepared-hydrated-audit')
        op.package_post()
        completed = True
    finally:
        finish_staging(op, sys.exception())
    need(completed, 'prepared-hydration-incomplete')
    return binding


def original_build_facts(op, origin, *, package_version):
    """Two finite pre-signing facts from the actual original build, not P bytes."""
    def retained(name, limit, modes=(0o400, 0o444, 0o600, 0o644)):
        entry = op.original(op.descend(op.work_entry, Path(name).parts[:-1]), Path(name).name,
                            'prepared-build-input', limit, modes)
        body = op.read(entry)
        op.package_outputs.append((entry, sha(body)))
        return body
    native = 'nativeScope' in origin
    need(retained('observer-build.status' if native else 'normal-build.status', 4) == b'0\n', 'prepared-original-build-zero')
    source = decode(retained('source-inventory.json', 2 * MIB), 2 * MIB)
    bound = decode(retained('source-binding.json', 65536), 65536)
    need(source.get('source') == bound.get('source') == origin['source']
         and source.get('tree') == bound.get('tree') == origin['tree']
         and bound.get('workflowSource') == origin['source'] and bound.get('runId') == origin['runId']
         and bound.get('runAttempt') == origin['runAttempt'] and bound.get('scope') == 'current-macos-candidate'
         and bound.get('instrumented') is native
         and bound.get('packageRole') == ('installed-shell-observation' if native else 'ordinary-image'), 'prepared-build-source')
    if native:
        binary = Path(op.environment.get('MRK_MACOS_OBSERVER_BINARY', ''))
        need(binary.is_absolute() and binary.parent == op.work / 'cargo-target' / op.target / 'debug/deps'
             and re.fullmatch(r'installed_shell_observation-[0-9a-f]+', binary.name), 'prepared-observer-path')
        compiled = op.stager.observer_cargo_artifact(retained('observer-build.jsonl', 8 * MIB), binary,
            op.work / 'cargo-target', retained(str(binary.relative_to(op.work)), PACKAGE_LIMIT, (0o444, 0o555, 0o644, 0o755)),
            target=op.target, package_version=package_version)
        entry = retained('mrk-macos-entry', MIB, (0o555, 0o755))
        op.stager.entry_macho(entry, target=op.target)
        app = decode(retained('app-result.json', RECEIPT_LIMIT), RECEIPT_LIMIT)
        need(app.get('packageRole') == 'installed-shell-observation'
             and app.get('observerCargoArtifact') == compiled
             and app.get('appBinarySha256BeforeSigning') == compiled['binarySha256']
             and app.get('entryBinarySha256BeforeSigning') == sha(entry)
             and 'desktopImageCargoArtifact' not in app, 'prepared-observer-originals')
        return {k: app[k] for k in ('appBinarySha256BeforeSigning', 'entryBinarySha256BeforeSigning')}
    path = 'cargo-target/' + op.target + '/release/libmrk_desktop_image.dylib'
    normal = op.stager.image_cargo_artifact(retained('normal-build.jsonl', 8 * MIB), op.work / path,
        op.work / 'cargo-target', retained(path, PACKAGE_LIMIT, (0o444, 0o555, 0o644, 0o755)), 'desktop', target=op.target, package_version=package_version)
    facade = retained('mobile-release-kit-desktop', MIB, (0o555, 0o755))
    op.stager.entry_macho(facade, target=op.target)
    app = decode(retained('app-result.json', RECEIPT_LIMIT), RECEIPT_LIMIT)
    need(app.get('packageRole') == 'ordinary-image' and app.get('desktopImageCargoArtifact') == normal
         and app.get('desktopImageSha256BeforeSigning') == normal['binarySha256']
         and app.get('appBinarySha256BeforeSigning') == sha(facade)
         and 'observerCargoArtifact' not in app and 'normalCargoArtifact' not in app, 'prepared-build-originals')
    return {key: app[key] for key in ('appBinarySha256BeforeSigning', 'desktopImageSha256BeforeSigning')}


class ResourceGuard:
    """One existing custodian, fixed read-only memory call; no new executor.

    Available VM counters are an estimate, not an OS reservation. A reserved
    codec window bounds per-leaf callbacks without one native call per leaf.
    """
    def __init__(self, op):
        self.op, self.quote = op, None
        self.samples = 0
        self.window = None
        from desktop.tools import macos_fixed_carrier_resume as resume
        self.data = resume
        op.normal_mount_host()  # Existing exact held SOURCE + Darwin ABI admission.

    def check(self, quote):
        import resource
        op = self.op
        need(type(quote) is dict and set(quote) == {'memoryBytes', 'diskBytes'}
             and all(type(v) is int and 0 < v < 1 << 53 for v in quote.values()), 'prepared-resource-quote')
        need(resource.getrlimit(resource.RLIMIT_NOFILE)[0] >= 256
             and len(op.entries) <= 24576 and sum(e['fd'] is not None or not e['closed'] for e in op.entries) + 40 <= 256,
             'prepared-original-resource-bound')
        self.samples += 1
        need(self.samples <= 16, 'prepared-resource-sample-bound')
        if op.environment.get('MRK_MACOS_RUNNER') in ('xcode-27', 'macos-26'):
            reclaim_prepared_allocator(op)
        result = op.call('prepared-resource-memory', ['/usr/bin/vm_stat'], op.native_environment(),
                         cwd=op.work, timeout=10, limit=65536)
        class Clock:
            def check(self): return op.package_clock()
        page, physical = self.data.host_memory_data(op.mount_api, Clock())
        memory = self.data.memory_data(result.stdout, result.stderr, result.returncode,
                                      page_size=page, physical_bytes=physical)
        disk = os.fstatvfs(op.work_entry['fd'])
        facts = self.data.resource_admission_data(memory['availableEstimateBytes'], quote['memoryBytes'],
                  disk.f_frsize * disk.f_bavail, quote['diskBytes'])
        op.prepared_resource_facts = facts
        need(facts['memorySufficient'] and facts['diskSufficient'], 'prepared-resource-insufficient')
        self.quote = dict(quote)
        op.package_post()

    def allocation(self, phase, live, packed, output):
        need(self.quote is not None and all(type(v) is int and 0 <= v <= 8 * PACKAGE_LIMIT for v in (live, packed, output)),
             'prepared-allocation-values')
        need(phase in ('xar-toc', 'xar-member', 'scripts-inflate', 'cpio-window', 'cpio-slice'), 'prepared-allocation-phase')
        required = live + 3 * packed + 2 * (output + 1) + 16 * MIB
        # The quote includes both retained packages and four actual expansion/
        # copy windows; no logical-size-only accounting or cap rise.
        need(required <= self.quote['memoryBytes'], 'prepared-codec-window')
        self.op.package_clock()


def reclaim_prepared_allocator(op):
    """Flush bounded retired allocations of THIS admitted macOS process.

    The cached mach_vm.defs declares this synchronous current-task operation. It
    releases already freed regions in the deferred reclamation buffer; it does
    not purge other processes or release live DATA. Admission still uses only
    the subsequent real vm_stat sample against the unchanged full quote.
    """
    import ctypes
    need(sys.platform == 'darwin' and op.prepared_staging and op.phase == 'package-install'
         and op.environment.get('MRK_MACOS_RUNNER') in ('xcode-27', 'macos-26'), 'prepared-allocator-host')
    op.package_clock()
    library = op.mount_api.library  # SAME libSystem instance admitted by normal_mount_host.
    current = library.mach_task_self
    current.argtypes, current.restype = [], ctypes.c_uint32
    flush = library.mach_vm_deferred_reclamation_buffer_flush
    flush.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint64),
                     ctypes.POINTER(ctypes.c_uint64)]
    flush.restype = ctypes.c_int
    task = current()
    need(type(task) is int and 0 < task < 2**32, 'prepared-allocator-host')
    reclaimed, deadline = ctypes.c_uint64(), ctypes.c_uint64()
    status = flush(task, 16384, ctypes.byref(reclaimed), ctypes.byref(deadline))
    op.package_clock()
    need(type(status) is int and -2**31 <= status < 2**31 and reclaimed.value < 1 << 53,
         'prepared-allocator-reclaim')
    op.prepared_allocator_facts = dict(requestedEntries=16384, bytesReclaimed=reclaimed.value,
                                      status=status, currentProcessOnly=True)
    need(status == 0, 'prepared-allocator-reclaim')


def selected_job_data(body, source, run, target, *, completed, native_scope=None, artifacts=None):
    value = decode(body, 8 * MIB)
    need(type(value) is dict and type(value.get('jobs')) is list and type(value.get('total_count')) is int
         and len(value['jobs']) == value['total_count'] <= 100, 'prepared-jobs-page-complete')
    need(native_scope is None or type(native_scope) is str and native_scope in NATIVE_HOSTS, 'prepared-job-scope')
    name = NATIVE_JOB_NAMES[native_scope] if native_scope else 'normal-installed-' + target
    rows = [row for row in value['jobs'] if type(row) is dict and row.get('name') == name]
    if completed:
        # All-attempt API page: select the exact successful checkpoint cut,
        # not its whole job's conclusion. Later unrelated cleanup may fail;
        # multiple completed checkpoint attempts still refuse, never latest.
        closed = []
        for row in rows:
            if row.get('status') != 'completed':
                continue
            try:
                producer_steps_data(row, native=native_scope is not None)
            except ValueError:
                continue
            closed.append(row)
        rows = closed
        if artifacts is not None:
            # GitHub copies successful jobs into a failed-job rerun with a new
            # job ID/attempt, even though no build or upload happened there.
            # Only an actual immutable artifact for that attempt can nominate it.
            listing = decode(artifacts, 8 * MIB)
            need(type(listing) is dict and type(listing.get('artifacts')) is list
                 and type(listing.get('total_count')) is int
                 and len(listing['artifacts']) == listing['total_count'] <= 100,
                 'prepared-artifact-page-complete')
            names = {a.get('name') for a in listing['artifacts'] if type(a) is dict}
            def retained(row):
                if type(row.get('run_attempt')) is not int or row['run_attempt'] <= 0:
                    return False
                prefix = ('macos-candidate-package-' + native_scope if native_scope else
                          'mobile-release-kit-macos26-' + target + '-prepared')
                return prefix + '-' + source + '-' + run + '-' + str(row['run_attempt']) in names
            rows = [row for row in rows if retained(row)]
    need(len(rows) == 1, 'prepared-one-target-job')
    row = rows[0]
    need(type(row.get('id')) is int and row['id'] > 0 and type(row.get('run_id')) is int and row['run_id'] == int(run)
         and row.get('head_sha') == source and type(row.get('run_attempt')) is int and row['run_attempt'] > 0,
         'prepared-job-context')
    if completed:
        producer_steps_data(row, native=native_scope is not None)
    return row


def selected_artifact_data(body, origin):
    value = decode(body, 8 * MIB)
    need(type(value) is dict and type(value.get('artifacts')) is list and type(value.get('total_count')) is int
         and len(value['artifacts']) == value['total_count'] <= 100, 'prepared-artifact-page-complete')
    rows = [row for row in value['artifacts'] if type(row) is dict and row.get('name') == artifact_name(origin)]
    need(len(rows) == 1 and type(rows[0].get('id')) is int and rows[0]['id'] > 0
         and rows[0].get('expired') is False and type(rows[0].get('size_in_bytes')) is int
         and 22 <= rows[0]['size_in_bytes'] <= ARTIFACT_LIMIT
         and type(rows[0].get('digest')) is str and rows[0]['digest'].startswith('sha256:')
         and hex_data(rows[0]['digest'][7:]), 'prepared-one-artifact')
    return rows[0]


def acquire_checkpoint(op, consumer):
    """Standard Action's fresh originals, complete metadata and consuming close.

    The action verifies the service ZIP digest; this owner reauthenticates its
    exact flat cohort. Neither an adjacent manifest nor a selection flag is
    sufficient. API originals have a separately saved successful caller status.
    """
    try:
        op.prepared_staging = True
        op.open()
        source_head(op, consumer['source'])
        import time
        op.package_started = op.package_observed = time.monotonic_ns()
        op.package_endpoint = op.package_started + 180_000_000_000
        root = op.directory(op.work_entry, 'prepared-input', 'prepared-transport-root')
        need(set(os.listdir(root['fd'])) == NAMES, 'prepared-transport-original-roster')
        marker = op.original(root, 'PREPARED.json', 'prepared-manifest-original', MANIFEST_LIMIT, (0o400, 0o444, 0o600, 0o644))
        marker_body = op.read(marker)
        manifest = manifest_data(decode(marker_body, MANIFEST_LIMIT))
        service_root = op.directory(op.work_entry, 'prepared-service', 'prepared-service-root')
        names = {'run.json', 'job.json', 'artifact.json', 'commit.json', 'metadata.status'}
        if (op.environment.get('MRK_MACOS_PREPARED_RESUME') == 'true'
            and manifest['origin']['source'] != consumer['source']):
            names.add('compatibility.json')
        need(set(os.listdir(service_root['fd'])) == names, 'prepared-service-original-roster')
        service = {}
        for name in sorted(names):
            original = op.original(service_root, name, 'prepared-service-original', 8 * MIB, (0o400, 0o444, 0o600, 0o644))
            body = op.read(original)
            op.package_outputs.append((original, sha(body)))
            if name == 'metadata.status':
                need(body == b'0\n', 'prepared-service-original-status')
            else:
                service[name[:-5]] = decode(body, 8 * MIB)
        commit = service.pop('commit')
        need(type(commit) is dict and commit.get('sha') == manifest['origin']['source']
             and type(commit.get('tree')) is dict and commit['tree'].get('sha') == manifest['origin']['tree'],
             'prepared-service-source-tree')
        metadata_data(service['run'], service['job'], service['artifact'], manifest)
        originals = {}
        for row in manifest['members']:
            entry = op.original(root, row['name'], 'prepared-member-original', FILES[row['name']], (0o400, 0o444, 0o600, 0o644))
            need(entry['identity'][6] == row['bytes'], 'prepared-member-original-size')
            originals[row['name']] = entry
        guard = ResourceGuard(op)
        guard.check(quote_data(originals['MobileReleaseKit.pkg']['identity'][6],
                              originals['MobileReleaseKit-original.pkg']['identity'][6], 1, 1))
        values = {'PREPARED.json': marker_body}
        for name, entry in originals.items():
            values[name] = read_prepared_member(op, name, entry)
            op.package_outputs.append((entry, sha(values[name])))
        binding = admit_data(values, service, consumer)
        op.package_outputs.append((marker, sha(marker_body)))
        op.package_roots.extend(((root, set(NAMES)), (service_root, names)))
        op.package_post()
    finally:
        finish_staging(op, sys.exception())
    return values, binding


def read_prepared_member(op, name, entry):
    """Same original read; avoid retaining a second package-sized file cache."""
    need(name in FILES, 'prepared-cohort-roster')
    if name in ('MobileReleaseKit.pkg', 'MobileReleaseKit-original.pkg'):
        # ResourceGuard has already admitted the actual Darwin SOURCE/ABI.
        # The flag is per-FD and changes no file bytes or filesystem metadata.
        import fcntl
        fcntl.fcntl(entry['fd'], fcntl.F_NOCACHE, 1)
    return op.read(entry)


def source_head(op, source):
    entry = op.source_original('.git/HEAD', 'prepared-detached-source', 64)
    body = op.read(entry)
    need(body == (source + '\n').encode('ascii'), 'prepared-exact-detached-source')
    op.package_sources.append((entry, body))


def native_binding(environment):
    """Re-admit the saved package using fresh owners; never change caller identity."""
    from types import SimpleNamespace
    from desktop.tools import macos_android_helper_package as helper
    need(environment.get('MRK_MACOS_PREPARED_TEST') == 'true' and native_origin(environment),
         'prepared-native-test-only')
    target = environment.get('MRK_MACOS_TARGET')
    work = admit_host(helper, environment, SimpleNamespace(target=target, phase='hydrate'))
    root = helper.CHECKOUT
    stager = helper.load_data(root, 'stage_macos_installed.py', '_mrk_native_prepared_stager')
    qualification = helper.load_data(root, 'macos_aqua_qualification.py', '_mrk_native_prepared_owner')
    owner = qualification.load_owner(root)
    operation = helper.Operation(owner, root, work, 'package-install', environment, stager, target=target)
    values, binding = acquire_checkpoint(operation, consumer_data(environment, environment.get('MRK_CONSUMER_TREE'), target))
    need(binding.native_compatible and binding.origin.get('nativeScope') == environment['MRK_MACOS_NATIVE_SCOPE'],
         'prepared-native-same-source')
    return binding, owner


# Only fixed public refusal codes are logged; arbitrary exception text is private.
PREPARED_FAILURE_CODES = frozenset({
    'prepared-allocator-host',
    'prepared-allocator-reclaim',
    'prepared-streamed-expansion-bound',
    'prepared-streamed-expansion-complete',
    'prepared-expansion-header',
    'prepared-expansion-index',
    'prepared-expansion-correspondence',
    'prepared-allocation-phase',
    'prepared-allocation-values',
    'prepared-api-original-status',
    'prepared-artifact-page-complete',
    'prepared-binding-constructor',
    'prepared-build-originals',
    'prepared-build-source',
    'prepared-built-source',
    'prepared-caller-status',
    'prepared-candidate-same-source-only',
    'prepared-codec-window',
    'prepared-cohort-bytes',
    'prepared-cohort-roster',
    'prepared-cohort-status',
    'prepared-consumer',
    'prepared-consumer-tree',
    'prepared-cross-source-install-only',
    'prepared-cross-source-not-candidate',
    'prepared-current-consumer',
    'prepared-current-source',
    'prepared-dispatch-install-only',
    'prepared-exact-detached-source',
    'prepared-export-attempt',
    'prepared-export-audit',
    'prepared-export-caller-zero',
    'prepared-export-incomplete',
    'prepared-export-origin',
    'prepared-export-original-package',
    'prepared-fixed-candidate-route',
    'prepared-fixed-entry',
    'prepared-fixed-store-profile',
    'prepared-harness-ancestor',
    'prepared-harness-files',
    'prepared-harness-history',
    'prepared-harness-source-tree',
    'prepared-harness-unnecessary',
    'prepared-hosted-context',
    'prepared-hosted-platform',
    'prepared-hydrated-audit',
    'prepared-hydration-binding',
    'prepared-hydration-incomplete',
    'prepared-job-context',
    'prepared-job-scope',
    'prepared-jobs-page-complete',
    'prepared-json-bound',
    'prepared-json-duplicate',
    'prepared-manifest',
    'prepared-manifest-bound',
    'prepared-member-binding',
    'prepared-member-count',
    'prepared-member-original-size',
    'prepared-native-origin',
    'prepared-native-resume-phase',
    'prepared-native-same-source',
    'prepared-native-selection',
    'prepared-native-test-only',
    'prepared-observer-originals',
    'prepared-observer-path',
    'prepared-one-artifact',
    'prepared-one-target-job',
    'prepared-origin',
    'prepared-origin-role',
    'prepared-original-build',
    'prepared-original-build-zero',
    'prepared-original-directory-census',
    'prepared-original-file-bound',
    'prepared-original-inventory',
    'prepared-original-resource-bound',
    'prepared-original-roster',
    'prepared-owned-work',
    'prepared-package-binding',
    'prepared-packager-identity',
    'prepared-resource-insufficient',
    'prepared-resource-quote',
    'prepared-resource-sample-bound',
    'prepared-resource-values',
    'prepared-selected-tree',
    'prepared-selection-context',
    'prepared-service-artifact',
    'prepared-service-cut',
    'prepared-service-job',
    'prepared-service-original-roster',
    'prepared-service-original-status',
    'prepared-service-records',
    'prepared-service-run',
    'prepared-service-shape',
    'prepared-service-source-tree',
    'prepared-service-steps',
    'prepared-staging-original-closes',
    'prepared-staging-owner',
    'prepared-transport-original-roster',
    'p0-memory-original',
    'p0-memory-lines',
    'p0-memory-header',
    'p0-memory-page-size',
    'p0-memory-counter',
    'p0-memory-bound',
    'resume-resource-diagnostic-bound',
})


def failure_data(error, phase, operation):
    reason = error.args[0] if type(error) is ValueError and len(error.args) == 1 else None
    known = type(reason) is str and reason in PREPARED_FAILURE_CODES
    return dict(kind='prepared-checkpoint-failure', phase=phase,
        reason=reason if known else 'unclassified', diagnosticOnly=True,
        resourceAdmission=getattr(operation, 'prepared_resource_facts', None),
        allocatorReclamation=getattr(operation, 'prepared_allocator_facts', None))


def main():
    """Fixed hosted entry; no arbitrary checkout, command or Installer path."""
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=('select', 'export', 'hydrate', 'package-install', 'finalize-image', 'candidate'))
    parser.add_argument('--target', required=True, choices=TARGETS)
    parser.add_argument('--producer-source')
    parser.add_argument('--producer-run')
    parser.add_argument('--consumer-tree')
    args = parser.parse_args()
    operation = None
    helper = None
    try:
        # Import only this fixed trusted checkout, never a prepared member.
        root = Path('/Users/runner/work/mobile-release-kit/mobile-release-kit')
        need(Path(__file__).absolute() == root / 'desktop/tools/macos_prepared_package.py', 'prepared-fixed-entry')
        sys.path.insert(0, str(root))
        from desktop.tools import macos_android_helper_package as helper
        environment = dict(os.environ)
        work = admit_host(helper, environment, args)
        need(environment['GITHUB_REF'] == 'refs/heads/' + BRANCH, 'prepared-fixed-candidate-route')
        stager = helper.load_data(root, 'stage_macos_installed.py', '_mrk_prepared_stager')
        need(stager.read(root / '.git/HEAD', 64) == (environment['GITHUB_SHA'] + '\n').encode('ascii'), 'prepared-current-source')
        qualification = helper.load_data(root, 'macos_aqua_qualification.py', '_mrk_prepared_owner_loader')
        owner = qualification.load_owner(root)
        if args.phase == 'select':
            need(hex_data(args.producer_source, 40) and decimal(args.producer_run), 'prepared-selection-context')
            operation = helper.Operation(owner, root, work, 'package-install', environment, stager, target=args.target)
            try:
                operation.prepared_staging = True
                operation.open()
                import time
                operation.package_started = operation.package_observed = time.monotonic_ns()
                operation.package_endpoint = operation.package_started + 180_000_000_000
                source_head(operation, environment['GITHUB_SHA'])
                def small(name):
                    entry = operation.original(operation.work_entry, name, 'prepared-api-original', 8 * MIB, (0o600,))
                    body = operation.read(entry)
                    operation.package_outputs.append((entry, sha(body)))
                    return body
                need(small('prepared-api.status') == b'0\n', 'prepared-api-original-status')
                artifact_body = small('prepared-artifacts.json')
                job = selected_job_data(small('prepared-jobs.json'), args.producer_source, args.producer_run, args.target,
                    completed=True, native_scope=native_origin(environment).get('nativeScope'), artifacts=artifact_body)
                commit = decode(small('prepared-commit.json'), 8 * MIB)
                need(commit.get('sha') == args.producer_source and type(commit.get('tree')) is dict
                     and hex_data(commit['tree'].get('sha'), 40), 'prepared-selected-tree')
                origin = origin_data(dict(source=args.producer_source, tree=commit['tree']['sha'], target=args.target,
                    runId=args.producer_run, runAttempt=str(job['run_attempt']), jobId=str(job['id']), **native_origin(environment)))
                artifact = selected_artifact_data(artifact_body, origin)
                directory = operation.package_directory('prepared-service')
                operation.package_file(directory, 'job.json', canonical(job))
                operation.package_file(directory, 'artifact.json', canonical(artifact))
                operation.package_file(directory, 'commit.json', canonical(commit))
                operation.package_post()
            finally:
                finish_staging(operation, sys.exception())
            # Finite output consumed by Actions; no caller-provided interpolation.
            print('artifact-id=' + str(artifact['id']))
            print('producer-attempt=' + origin['runAttempt'])
            print('producer-source=' + origin['source'])
            return 0
        if args.phase == 'export':
            operation = helper.Operation(owner, root, work, 'package-install', environment, stager, target=args.target)
            # Exporter repeats the held originals again; these small detached
            # source/job records only nominate the exact tuple, never the cut.
            source = decode(stager.read(work / 'source-inventory.json', 2 * MIB), 2 * MIB)
            need(stager.read(work / 'prepared-api.status', 4) == b'0\n', 'prepared-api-original-status')
            job = selected_job_data(stager.read(work / 'prepared-jobs.json', 8 * MIB), environment['GITHUB_SHA'],
                                    environment['GITHUB_RUN_ID'], args.target, completed=False, native_scope=native_origin(environment).get('nativeScope'))
            need(str(job['run_attempt']) == environment['GITHUB_RUN_ATTEMPT'], 'prepared-export-attempt')
            export_checkpoint(operation, dict(source=environment['GITHUB_SHA'], tree=source['tree'], target=args.target,
                runId=environment['GITHUB_RUN_ID'], runAttempt=environment['GITHUB_RUN_ATTEMPT'], jobId=str(job['id']), **native_origin(environment)))
            return 0
        need(hex_data(args.consumer_tree, 40), 'prepared-consumer-tree')
        consumer = consumer_data(environment, args.consumer_tree, args.target)
        operation = helper.Operation(owner, root, work, 'package-install', environment, stager, target=args.target)
        values, binding = acquire_checkpoint(operation, consumer)
        built_root = root if binding.same_source else root / 'prepared-built-source'
        need(stager.read(built_root / '.git/HEAD', 64) == (binding.source + '\n').encode('ascii'), 'prepared-built-source')
        if not binding.same_source:
            stager = helper.load_data(built_root, 'stage_macos_installed.py', '_mrk_prepared_built_stager')
        manifest = binding.manifest
        environment.update(MRK_MACOS_INSTALL_SOURCE_COMMIT=binding.source,
            MRK_MACOS_INSTALL_INVENTORY_SHA256=manifest['inventorySha256'],
            MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=manifest['runtimeManifestSha256'])
        if args.phase == 'hydrate':
            operation = helper.Operation(owner, built_root, work, 'package-install', environment, stager,
                                         target=args.target, prepared=binding)
            hydrate_checkpoint(operation, values, binding)
            print('MRK_MACOS_INSTALL_INVENTORY_SHA256=' + manifest['inventorySha256'])
            print('MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=' + manifest['runtimeManifestSha256'])
            return 0
        del values  # Admission copies no longer overlap compiler/image work.
        if args.phase == 'candidate':
            need(environment['GITHUB_EVENT_NAME'] == 'push' and binding.same_source, 'prepared-cross-source-not-candidate')
            result = stager.preview_command(argparse.Namespace(target=args.target, expected_source=binding.source,
                work=work, output=work / 'candidate', candidate_carrier=True, installed_passive_carrier=False), prepared=binding)
            print(json.dumps(result, sort_keys=True))
            return 0
        need(args.phase == 'package-install' or environment['GITHUB_EVENT_NAME'] == 'push' and binding.same_source, 'prepared-cross-source-install-only')
        operation = helper.Operation(owner, built_root, work, args.phase, environment, stager, target=args.target, prepared=binding)
        operation.execute()
        if environment['GITHUB_EVENT_NAME'] == 'workflow_dispatch':
            # This distinct stdout observation never becomes a V2 candidate.
            print(json.dumps(dict(schemaVersion=1, scope='prepared-input-fresh-installer-observation',
                producer=binding.origin, consumer=binding.consumer, installed=True, productReady=False,
                actualPackageOwnerReturned=True, originalClosesKnown=operation.receipt['originalClosesKnown']), sort_keys=True))
        return 0
    except BaseException as error:
        print('Prepared signed-input refused; no installed candidate accepted.', file=sys.stderr)
        print(json.dumps(failure_data(error, args.phase, operation), sort_keys=True), file=sys.stderr)
        if helper is not None:
            helper.emit_failure_diagnostic(error, phase=args.phase, target=args.target, main_stage='operation-execute',
                                           operation=operation, stager=getattr(operation, 'stager', None))
        return 1


def admit_host(helper, environment, args):
    if environment.get('GITHUB_EVENT_NAME') == 'push' or (
        environment.get('MRK_MACOS_PREPARED_RESUME') == 'true' and native_origin(environment)):
        need(args.phase in ('select', 'hydrate', 'package-install')
             or environment.get('GITHUB_EVENT_NAME') == 'push', 'prepared-native-resume-phase')
        return helper.admit(environment, target=args.target, phase='package-install')
    # Diagnostic-only current harness. Never change the actual event/source or
    # let ordinary helper.admit accept dispatch/artifact claims as push evidence.
    need(args.phase in ('select', 'hydrate', 'package-install') and environment.get('GITHUB_EVENT_NAME') == 'workflow_dispatch',
         'prepared-dispatch-install-only')
    machine, arch, _ = helper.build_profile(args.target)
    source = environment.get('GITHUB_SHA')
    need(sys.platform == 'darwin' and sys.maxsize == 2**63-1 and os.uname().machine == machine
         and os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid()
         and hex_data(source, 40), 'prepared-hosted-platform')
    required = dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='macOS', RUNNER_ARCH=arch,
        GITHUB_REPOSITORY=REPOSITORY, GITHUB_REF='refs/heads/' + BRANCH, GITHUB_WORKSPACE=str(helper.CHECKOUT),
        GITHUB_WORKFLOW_SHA=source, GITHUB_WORKFLOW_REF=REPOSITORY + '/' + WORKFLOW + '@refs/heads/' + BRANCH,
        MRK_EXPECTED_SHA=source, MRK_MACOS_INSTALL_SOURCE_COMMIT=source, MRK_MACOS_PACKAGE_ROLE='ordinary-image',
        MRK_MACOS_STORE_RUNTIME='signed-component', MRK_MACOS_SAME_PACKAGE_SCOPE='disabled',
        RUSTUP_TOOLCHAIN=helper.rust_toolchain(args.target), DEVELOPER_DIR='/Library/Developer/CommandLineTools',
        MACOSX_DEPLOYMENT_TARGET='26.0')
    need(all(environment.get(k) == v for k,v in required.items())
         and all(decimal(environment.get(k)) for k in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT')), 'prepared-hosted-context')
    work = Path(environment.get('MRK_MACOS_WORK', ''))
    need(work.parent == helper.WORK_PARENT and re.fullmatch(r'mrk-macos-installed\.[A-Za-z0-9]{8}', work.name), 'prepared-owned-work')
    return work


if __name__ == '__main__':
    # One canonical module/type throughout helper, stager and this entry.
    root = Path('/Users/runner/work/mobile-release-kit/mobile-release-kit')
    need(Path(__file__).absolute() == root / 'desktop/tools/macos_prepared_package.py', 'prepared-fixed-entry')
    sys.path.insert(0, str(root))
    from desktop.tools.macos_prepared_package import main as entry
    raise SystemExit(entry())
