"""Service/native facts are inert DATA; no downloaded/native code runs here."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


TOOL = load('store_signed_component_test', 'desktop/tools/macos_store_component.py')
FIXTURE = load('store_signed_data_fixture', 'tests/desktop/test_macos_store_signing.py')
SOURCE = 'a' * 40
CARRIER_SOURCE = 'b' * 40


def zipped(entries):
    body = io.BytesIO()
    with zipfile.ZipFile(body, 'w') as archive, warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)  # Deliberately duplicated inert names.
        for name, content in entries:
            archive.writestr(name, content)
    return body.getvalue()


class SignedStoreComponent(unittest.TestCase):
    def fixture(self, arch):
        target = 'aarch64-apple-darwin' if arch == 'arm64' else 'x86_64-apple-darwin'
        cpu, subtype = (0x100000c, 0) if arch == 'arm64' else (0x1000007, 3)
        data = [(name, FIXTURE.native(signed=True, cpu=cpu, subtype=subtype,
                kind=2 if name == 'runtime/bin/ruby' else 8) if body[:4] in FIXTURE.M.MAGICS else body, kind)
                for name, body, kind in FIXTURE.fixture()]
        archive = FIXTURE.tar(data)
        rows = FIXTURE.M.archive_scan(archive, lambda *_: None)
        producer = (ROOT / 'desktop/packaging/macos-install-producer-signing.profile').read_bytes()
        service = (ROOT / 'desktop/packaging/macos-android-service-signing.profile').read_bytes()
        policy = FIXTURE.STAGER.packaging_signing_data(producer, service)
        identity = FIXTURE.STAGER.service_signing_data(service)
        receipt = {'schemaVersion': 1, 'kind': 'macos-store-signed-v1', 'source': SOURCE, 'runId': '100',
            'runAttempt': '1', 'target': target,
            'workflow': TOOL.REPOSITORY + '/.github/workflows/desktop-macos-python-runtime-signing.yml@refs/heads/verify/desktop-macos-store-signing',
            'signer': {'teamIdentifier': identity[0], 'certificateSha1': identity[1],
                'producerProfileSha256': policy.producer_sha256, 'serviceProfileSha256': policy.service_sha256},
            'originalsClosed': True, 'sourcePost': True, 'inputPost': True, 'nonNativeUnchanged': True,
            'outerExitRequired': True, 'nativeCallCount': len(FIXTURE.M.ROLES), 'credentialCallCount': 19,
            'credentialContexts': [{'purpose': FIXTURE.M.PHASE, 'closed': True, 'retired': True,
                                   'searchRestored': True, 'defaultUnchanged': True}],
            'signedArchiveSha256': hashlib.sha256(archive).hexdigest(), 'signedArchiveBytes': len(archive),
            'signedInventorySha256': FIXTURE.M.sha(FIXTURE.M.canonical(rows)),
            'inputNativeCount': FIXTURE.M.INPUT_NATIVE_COUNT, 'outputNativeCount': FIXTURE.M.NATIVE_COUNT,
            'inputMemberCount': len(rows) + 55, 'outputMemberCount': len(rows),
            'nonNativeUnchangedScope': 'retained-after-declared-projection',
            'omittedInstallCaches': [{'path': FIXTURE.M.NOTIFIER_CACHE_PATH,
                'sha256': FIXTURE.M.NOTIFIER_CACHE_SHA256, 'bytes': FIXTURE.M.NOTIFIER_CACHE_BYTES}],
            'omittedBuildObjects': [{'path': name, 'bytes': len(body), 'sha256': FIXTURE.M.sha(body)}
                for name, body, _ in FIXTURE.build_objects(cpu=cpu, subtype=subtype)],
            'nativeMembers': [{'path': row['path'], 'signedBytes': row['bytes'], 'signedSha256': row['sha256'],
                              'identifier': FIXTURE.M.identifier(row['path']), 'codeDirectoryFlags': [0x10000]}
                             for row in rows if row['native']]}
        run = {'id': 100, 'repository': {'full_name': TOOL.REPOSITORY}, 'head_repository': {'full_name': TOOL.REPOSITORY},
               'head_branch': 'verify/desktop-macos-store-signing', 'head_sha': SOURCE, 'event': 'push', 'workflow_id': 20}
        workflow = {'id': 20, 'path': '.github/workflows/desktop-macos-python-runtime-signing.yml'}
        artifact = {'id': 300, 'name': f'store-signed-{target}-100-1', 'expired': False,
                    'workflow_run': {'id': 100, 'head_sha': SOURCE}}
        jobs = {'total_count': 1, 'jobs': [{'name': f'Store signing ({arch})', 'run_id': 100, 'run_attempt': 1,
                'head_sha': SOURCE, 'status': 'completed', 'conclusion': 'success'}]}
        return archive, receipt, run, workflow, artifact, jobs

    def attempt(self, root, arch, fixture, *, expected_attempt=None):
        archive, receipt, run, workflow, artifact, jobs = fixture
        transport = io.BytesIO()
        with zipfile.ZipFile(transport, 'w') as target:
            target.writestr('store-signed.tar.gz', archive)
            target.writestr('store-signed-receipt.json', json.dumps(receipt))
        body = transport.getvalue()
        artifact.update(size_in_bytes=len(body), digest='sha256:' + hashlib.sha256(body).hexdigest())
        responses = {'actions/runs/100': run, 'actions/workflows/desktop-macos-python-runtime-signing.yml': workflow,
            'actions/artifacts/300': artifact, 'actions/runs/100/attempts/1/jobs?per_page=100': jobs}
        def download(argv, *, stdout, check, timeout):
            self.assertEqual(argv, ['gh', 'api', f'repos/{TOOL.REPOSITORY}/actions/artifacts/300/zip'])
            stdout.write(body)
        with mock.patch.object(TOOL, 'api', side_effect=lambda route: responses[route]), \
                mock.patch.object(TOOL.subprocess, 'run', side_effect=download):
            return TOOL.restore_signed(root, 100, SOURCE, arch, 300, expected_attempt=expected_attempt)

    def test_exact_architecture_complete_roster_and_service_project_without_execution(self):
        for arch in ('arm64', 'x86_64'):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / 'projection'
                fixture = self.fixture(arch)
                result = self.attempt(root, arch, fixture)
                self.assertEqual((result / 'licenses/NOTICE').read_bytes(), b'Keep every original notice byte\n')
                self.assertEqual(len([p for p in result.rglob('*') if p.is_file()]), FIXTURE.M.NATIVE_COUNT + 2)
                self.assertEqual(json.loads((root / 'signed-origin.json').read_bytes())['artifactId'], 300)
                self.assertFalse((root / 'artifact.zip').exists())
                with self.assertRaises(FileExistsError): self.attempt(root, arch, fixture)

    def test_source_selected_attempt_refuses_before_any_transport(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'projection'
            with self.assertRaisesRegex(ValueError, 'SOURCE-selected signed Store attempt differs'):
                self.attempt(root, 'arm64', self.fixture('arm64'), expected_attempt=2)
            self.assertFalse(root.exists())

    def test_wrong_origin_incomplete_closure_signer_or_full_inventory_refuse(self):
        fixture = self.fixture('arm64')
        changes = ('job', 'branch', 'source', 'calls', 'closure', 'identity', 'inventory', 'native', 'native-duplicate', 'object-roster', 'projection-count', 'cache-omission', 'cache-count', 'cache-scope')
        for changed in changes:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                data = copy.deepcopy(fixture)
                if changed == 'cache-omission': data[1]['omittedInstallCaches'] = []
                if changed == 'cache-count': data[1]['inputMemberCount'] -= 1
                if changed == 'cache-scope': del data[1]['nonNativeUnchangedScope']
                if changed == 'object-roster': data[1]['omittedBuildObjects'][0]['path'] = 'runtime/other.o'
                if changed == 'projection-count': data[1]['outputNativeCount'] = 187
                if changed == 'job': data[5]['jobs'][0]['conclusion'] = 'failure'
                elif changed == 'branch': data[2]['head_branch'] = 'main'
                elif changed == 'source': data[1]['source'] = 'b' * 40
                elif changed == 'calls': data[1]['nativeCallCount'] = 372
                elif changed == 'closure': data[1]['credentialContexts'][0]['retired'] = False
                elif changed == 'identity': data[1]['signer']['teamIdentifier'] = 'FOREIGN001'
                elif changed == 'inventory': data[1]['signedInventorySha256'] = 'b' * 64
                elif changed == 'native': data[1]['nativeMembers'][0]['signedSha256'] = 'b' * 64
                elif changed == 'native-duplicate': data[1]['nativeMembers'][1] = data[1]['nativeMembers'][0]
                root = Path(temporary) / 'projection'
                with self.assertRaises(ValueError): self.attempt(root, 'arm64', data)
                self.assertFalse((root / 'extracted').exists())

    def retained_fixture(self, *, arch='arm64', original=None):
        original = original or self.fixture(arch)
        archive, receipt, run, workflow, artifact, jobs = original
        target = FIXTURE.STAGER.ARM_TARGET if arch == 'arm64' else FIXTURE.STAGER.INTEL_TARGET
        artifact_id = 300 if arch == 'arm64' else 301
        inner = zipped([('store-signed.tar.gz', archive), ('store-signed-receipt.json', json.dumps(receipt))])
        artifact.update(id=artifact_id, size_in_bytes=len(inner), digest='sha256:' + hashlib.sha256(inner).hexdigest())
        outer = zipped([(TOOL.ORIGINAL_ZIP, inner)])
        transport = {'kind': 'retained-actions', 'source': CARRIER_SOURCE, 'runId': '200',
                     'runAttempt': '1', 'artifactId': '400', 'bytes': len(outer),
                     'digest': 'sha256:' + hashlib.sha256(outer).hexdigest()}
        pinned = {'source': SOURCE, 'runId': '100', 'runAttempt': '1', 'artifactId': str(artifact_id),
                  'digest': artifact['digest'], 'bytes': len(inner)}
        selection = {'schemaVersion': 1, 'state': 'configured', 'source': SOURCE, 'runId': '100',
                     'runAttempt': '1', 'artifacts': {FIXTURE.STAGER.ARM_TARGET: '300', FIXTURE.STAGER.INTEL_TARGET: '301'}}
        nomination = {'schemaVersion': 1, 'targets': {FIXTURE.STAGER.ARM_TARGET: None, FIXTURE.STAGER.INTEL_TARGET: None}}
        if arch == 'arm64':
            nomination['targets'][target] = {'original': pinned, 'transport': transport}
        carrier = {'id': 400, 'name': f'store-signed-retained-{target}-200-1', 'expired': False,
                   'workflow_run': {'id': 200, 'head_sha': CARRIER_SOURCE},
                   'size_in_bytes': len(outer), 'digest': transport['digest']}
        responses = {'actions/runs/100': run, 'actions/workflows/desktop-macos-python-runtime-signing.yml': workflow,
            f'actions/artifacts/{artifact_id}': artifact, 'actions/runs/100/attempts/1/jobs?per_page=100': jobs,
            'actions/runs/200': dict(run, id=200, workflow_id=21, head_sha=CARRIER_SOURCE,
                                   head_branch=TOOL.RETAINED_BRANCH, event='workflow_dispatch'),
            'actions/workflows/desktop-macos-components.yml': {'id': 21, 'path': TOOL.RETAINED_WORKFLOW},
            'actions/artifacts/400': carrier,
            'actions/runs/200/attempts/1/jobs?per_page=100': {'total_count': 1, 'jobs': [
                {'name': TOOL.RETAINED_JOB, 'run_id': 200, 'run_attempt': 1, 'head_sha': CARRIER_SOURCE,
                 'status': 'completed', 'conclusion': 'success'}]}}
        return {'selection': selection, 'nomination': nomination, 'responses': responses, 'inner': inner,
                'target': target, 'downloads': {f'actions/artifacts/{artifact_id}/zip': inner,
                                               'actions/artifacts/400/zip': outer}}

    @contextlib.contextmanager
    def selected_context(self, data, root, *, during_download=None):
        desktop = root / 'source' / 'desktop'
        inputs = desktop / 'macos-installed-inputs'
        inputs.mkdir(parents=True)
        source = inputs / 'store-signed-component.json'
        nomination = desktop / TOOL.RETAINED_SELECTION
        source.write_text(json.dumps(data['selection']))
        nomination.write_text(json.dumps(data['nomination']))
        calls = {'api': [], 'downloads': []}
        def api(route):
            calls['api'].append(route)
            self.assertIn(route, data['responses'], 'No expired-original lookup or alternate discovery')
            return data['responses'][route]
        def download(argv, *, stdout, check, timeout):
            self.assertEqual(argv[:2], ['gh', 'api'])
            self.assertTrue(check)
            self.assertEqual(timeout, 180)
            prefix = f'repos/{TOOL.REPOSITORY}/'
            self.assertTrue(argv[2].startswith(prefix))
            route = argv[2].removeprefix(prefix)
            self.assertIn(route, data['downloads'], 'No native command, alternate download or retry')
            calls['downloads'].append(route)
            stdout.write(data['downloads'][route])
            if during_download is not None:
                during_download(source, nomination)
        with mock.patch.object(TOOL, '_source_selector', return_value=FIXTURE.STAGER), \
                mock.patch.object(FIXTURE.STAGER, 'DESKTOP', desktop), \
                mock.patch.object(TOOL, 'api', side_effect=api), \
                mock.patch.object(TOOL.subprocess, 'run', side_effect=download):
            yield calls

    def replace_outer(self, data, body):
        transport = data['nomination']['targets'][FIXTURE.STAGER.ARM_TARGET]['transport']
        transport.update(bytes=len(body), digest='sha256:' + hashlib.sha256(body).hexdigest())
        data['responses']['actions/artifacts/400'].update(size_in_bytes=len(body), digest=transport['digest'])
        data['downloads']['actions/artifacts/400/zip'] = body

    def test_retention_source_records_bind_original_and_explicit_routes(self):
        data = self.retained_fixture()
        selected = FIXTURE.STAGER.signed_store_selection_data(json.dumps(data['selection']).encode())
        good = data['nomination']
        actual = TOOL.retained_selection_data(json.dumps(good).encode(), selected, FIXTURE.STAGER)
        self.assertEqual(actual, good['targets'][selected['target']])
        changes = ('schema', 'targets', 'extra', 'source', 'run', 'attempt', 'artifact', 'digest', 'bytes',
                   'kind', 'carrier-source', 'carrier-run', 'carrier-attempt', 'carrier-artifact',
                   'carrier-digest', 'carrier-bytes', 'carrier-oversize', 'unknown-target', 'intel-retained')
        for change in changes:
            with self.subTest(change=change):
                bad = copy.deepcopy(good)
                row = bad['targets'][selected['target']]
                original, transport = row['original'], row['transport']
                if change == 'schema': bad['schemaVersion'] = True
                elif change == 'targets': bad['targets'] = []
                elif change == 'extra': bad['fallback'] = True
                elif change == 'source': original['source'] = CARRIER_SOURCE
                elif change == 'run': original['runId'] = '101'
                elif change == 'attempt': original['runAttempt'] = '2'
                elif change == 'artifact': original['artifactId'] = '301'
                elif change == 'digest': original['digest'] = 'sha256:bad'
                elif change == 'bytes': original['bytes'] = True
                elif change == 'kind': transport['kind'] = 'latest'
                elif change == 'carrier-source': transport['source'] = 'b' * 39
                elif change == 'carrier-run': transport['runId'] = 200
                elif change == 'carrier-attempt': transport['runAttempt'] = '01'
                elif change == 'carrier-artifact': transport['artifactId'] = '9007199254740992'
                elif change == 'carrier-digest': transport['digest'] = None
                elif change == 'carrier-bytes': transport['bytes'] = False
                elif change == 'carrier-oversize': transport['bytes'] = TOOL.RETAINED_ZIP_LIMIT + 1
                elif change == 'unknown-target': bad['targets']['foreign'] = None
                elif change == 'intel-retained': bad['targets'][FIXTURE.STAGER.INTEL_TARGET] = copy.deepcopy(row)
                with self.assertRaises(ValueError):
                    TOOL.retained_selection_data(json.dumps(bad).encode(), selected, FIXTURE.STAGER)
        for body in (b'', b' ' * (TOOL.RETAINED_SELECTION_LIMIT + 1),
                     b'{"schemaVersion":1,"schemaVersion":1,"targets":{}}',
                     b'{"schemaVersion":NaN,"targets":{}}'):
            with self.assertRaises((ValueError, FIXTURE.STAGER.Refused)):
                TOOL.retained_selection_data(body, selected, FIXTURE.STAGER)

    def test_copy_keeps_exact_original_zip_without_payload_projection(self):
        data = self.retained_fixture()
        data['nomination']['targets'][data['target']]['transport'] = {'kind': 'original'}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.selected_context(data, root) as calls, \
                    mock.patch.object(TOOL, '_project_signed', side_effect=AssertionError('No payload parser in copy')), \
                    mock.patch.object(TOOL, '_extract_component', side_effect=AssertionError('No payload extraction')):
                output = root / 'retained'
                result = TOOL.retain_selected(output, data['target'])
                self.assertEqual(result, output / TOOL.ORIGINAL_ZIP)
                self.assertEqual(list(output.iterdir()), [result])
                self.assertEqual(result.read_bytes(), data['inner'])
                self.assertEqual(calls['downloads'], ['actions/artifacts/300/zip'])
                self.assertNotIn('actions/runs/200', calls['api'])
                with self.assertRaises(FileExistsError): TOOL.retain_selected(output, data['target'])
                self.assertEqual(result.read_bytes(), data['inner'])

    def test_copy_refuses_unpinned_expired_changed_or_incomplete_original(self):
        fixture = self.retained_fixture()
        for change in ('unpinned', 'already-retained', 'expired', 'source-digest', 'service-size', 'job', 'download'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                data = copy.deepcopy(fixture)
                row = data['nomination']['targets'][data['target']]
                row['transport'] = {'kind': 'original'}
                if change == 'unpinned': data['nomination']['targets'][data['target']] = None
                elif change == 'already-retained': row['transport'] = fixture['nomination']['targets'][data['target']]['transport']
                elif change == 'expired': data['responses']['actions/artifacts/300']['expired'] = True
                elif change == 'source-digest': row['original']['digest'] = 'sha256:' + '0' * 64
                elif change == 'service-size': data['responses']['actions/artifacts/300']['size_in_bytes'] += 1
                elif change == 'job': data['responses']['actions/runs/100/attempts/1/jobs?per_page=100']['jobs'][0]['conclusion'] = 'failure'
                elif change == 'download': data['downloads']['actions/artifacts/300/zip'] = b'changed'
                root = Path(temporary)
                with self.selected_context(data, root) as calls, self.assertRaises(ValueError):
                    TOOL.retain_selected(root / 'retained', data['target'])
                self.assertNotIn('actions/artifacts/400/zip', calls['downloads'])

    def test_selected_retention_keeps_original_origin_and_complete_parser(self):
        data = self.retained_fixture()
        # An expired/deleted original transport is deliberately unavailable.
        del data['responses']['actions/artifacts/300']
        del data['downloads']['actions/artifacts/300/zip']
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.selected_context(data, root) as calls:
                result = TOOL.restore_selected(root / 'projection', data['target'])
                self.assertEqual((result / 'licenses/NOTICE').read_bytes(), b'Keep every original notice byte\n')
                self.assertEqual(len([p for p in result.rglob('*') if p.is_file()]), FIXTURE.M.NATIVE_COUNT + 2)
                origin = json.loads((root / 'projection/signed-origin.json').read_bytes())
                pinned = data['nomination']['targets'][data['target']]
                self.assertEqual((origin['source'], origin['runId'], origin['runAttempt'], origin['artifactId']),
                                 (SOURCE, 100, 1, 300))
                self.assertEqual(origin['artifactDigest'], pinned['original']['digest'])
                self.assertEqual(origin['retainedTransport'], pinned['transport'])
                self.assertNotEqual(origin['artifactDigest'], origin['retainedTransport']['digest'])
                binding, members, _ = FIXTURE.STAGER.store_component_inputs(root / 'projection', data['target'])
                self.assertEqual(binding['artifactDigest'], pinned['original']['digest'])
                self.assertEqual(binding['artifactId'], '300')
                self.assertEqual(len(members), FIXTURE.M.NATIVE_COUNT + 2)
                self.assertEqual(calls['downloads'], ['actions/artifacts/400/zip'])
                self.assertIn('actions/runs/100/attempts/1/jobs?per_page=100', calls['api'])
                self.assertIn('actions/runs/200/attempts/1/jobs?per_page=100', calls['api'])
                self.assertFalse((root / 'projection/artifact.zip').exists())
                self.assertFalse((root / 'projection/retained-transport.zip').exists())

    def test_retained_context_and_independent_digest_failures_never_fallback(self):
        fixture = self.retained_fixture()
        changes = ('original-job', 'original-branch', 'original-workflow', 'event', 'branch', 'source', 'repository',
                   'head-repository', 'workflow', 'workflow-id', 'artifact', 'artifact-name', 'expired',
                   'artifact-run', 'artifact-source', 'attempt', 'job', 'job-source', 'job-attempt', 'job-name',
                   'job-running', 'job-duplicate', 'jobs-bound', 'carrier-digest', 'carrier-size',
                   'original-digest', 'original-size', 'download')
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                data = copy.deepcopy(fixture)
                responses = data['responses']
                run = responses['actions/runs/200']
                artifact = responses['actions/artifacts/400']
                jobs = responses['actions/runs/200/attempts/1/jobs?per_page=100']
                row = data['nomination']['targets'][data['target']]
                if change == 'original-job': responses['actions/runs/100/attempts/1/jobs?per_page=100']['jobs'][0]['conclusion'] = 'failure'
                elif change == 'original-branch': responses['actions/runs/100']['head_branch'] = TOOL.RETAINED_BRANCH
                elif change == 'original-workflow': responses['actions/workflows/desktop-macos-python-runtime-signing.yml']['path'] = TOOL.RETAINED_WORKFLOW
                elif change == 'event': run['event'] = 'push'
                elif change == 'branch': run['head_branch'] = 'main'
                elif change == 'source': run['head_sha'] = SOURCE
                elif change == 'repository': run['repository'] = {'full_name': 'foreign/repository'}
                elif change == 'head-repository': run['head_repository'] = {'full_name': 'foreign/fork'}
                elif change == 'workflow': responses['actions/workflows/desktop-macos-components.yml']['path'] = 'foreign.yml'
                elif change == 'workflow-id': run['workflow_id'] = 20
                elif change == 'artifact': artifact['id'] = 401
                elif change == 'artifact-name': artifact['name'] += '-other'
                elif change == 'expired': artifact['expired'] = True
                elif change == 'artifact-run': artifact['workflow_run']['id'] = 201
                elif change == 'artifact-source': artifact['workflow_run']['head_sha'] = SOURCE
                elif change == 'attempt': row['transport']['runAttempt'] = '2'
                elif change == 'job': jobs['jobs'][0]['conclusion'] = 'failure'
                elif change == 'job-source': jobs['jobs'][0]['head_sha'] = SOURCE
                elif change == 'job-attempt': jobs['jobs'][0]['run_attempt'] = 2
                elif change == 'job-name': jobs['jobs'][0]['name'] = 'Store signing (arm64)'
                elif change == 'job-running': jobs['jobs'][0]['status'] = 'in_progress'
                elif change == 'job-duplicate': jobs['jobs'].append(copy.deepcopy(jobs['jobs'][0])); jobs['total_count'] = 2
                elif change == 'jobs-bound': jobs['total_count'] = 101
                elif change == 'carrier-digest': row['transport']['digest'] = 'sha256:' + '0' * 64
                elif change == 'carrier-size': row['transport']['bytes'] += 1
                elif change == 'original-digest': row['original']['digest'] = 'sha256:' + '0' * 64
                elif change == 'original-size': row['original']['bytes'] += 1
                elif change == 'download': data['downloads']['actions/artifacts/400/zip'] = b'changed'
                root = Path(temporary)
                with self.selected_context(data, root) as calls, self.assertRaises(ValueError):
                    TOOL.restore_selected(root / 'projection', data['target'])
                self.assertNotIn('actions/artifacts/300', calls['api'])
                self.assertNotIn('actions/artifacts/300/zip', calls['downloads'])
                self.assertLessEqual(len(calls['downloads']), 1)
                self.assertFalse((root / 'projection/extracted').exists())

    def test_retained_outer_roster_and_exact_inner_zip_are_mandatory(self):
        fixture = self.retained_fixture()
        inner = fixture['inner']
        link = zipfile.ZipInfo(TOOL.ORIGINAL_ZIP)
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        encrypted = bytearray(zipped([(TOOL.ORIGINAL_ZIP, inner)]))
        encrypted[6] |= 1
        encrypted[encrypted.rfind(b'PK\x01\x02') + 8] |= 1
        # Same archive/receipt contents with changed ZIP bytes are not the
        # original GitHub service archive pinned independently in SOURCE.
        repacked = inner + b'changed-zip-tail'
        cases = {'empty': zipped([]), 'extra': zipped([(TOOL.ORIGINAL_ZIP, inner), ('extra', b'x')]),
                 'duplicate': zipped([(TOOL.ORIGINAL_ZIP, inner), (TOOL.ORIGINAL_ZIP, inner)]),
                 'traversal': zipped([('../' + TOOL.ORIGINAL_ZIP, inner)]),
                 'directory': zipped([(TOOL.ORIGINAL_ZIP + '/', inner)]),
                 'link': zipped([(link, inner)]), 'encrypted': bytes(encrypted),
                 'short': zipped([(TOOL.ORIGINAL_ZIP, inner[:-1])]),
                 'repacked': zipped([(TOOL.ORIGINAL_ZIP, repacked)]),
                 'changed': zipped([(TOOL.ORIGINAL_ZIP, inner[:-1] + bytes([inner[-1] ^ 1]))])}
        for change, body in cases.items():
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                data = copy.deepcopy(fixture)
                self.replace_outer(data, body)  # The new service digest alone passes.
                root = Path(temporary)
                with self.selected_context(data, root) as calls, self.assertRaises(ValueError):
                    TOOL.restore_selected(root / 'projection', data['target'])
                self.assertEqual(calls['downloads'], ['actions/artifacts/400/zip'])
                self.assertFalse((root / 'projection/extracted').exists())

    def test_retained_bytes_still_require_original_signer_receipt_and_inventory(self):
        for change in ('receipt-source', 'signer', 'closure', 'inventory', 'native'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                original = self.fixture('arm64')
                if change == 'receipt-source': original[1]['source'] = CARRIER_SOURCE
                elif change == 'signer': original[1]['signer']['teamIdentifier'] = 'FOREIGN001'
                elif change == 'closure': original[1]['credentialContexts'][0]['retired'] = False
                elif change == 'inventory': original[1]['signedInventorySha256'] = '0' * 64
                elif change == 'native': original[1]['nativeMembers'][0]['signedSha256'] = '0' * 64
                # Both service digests and SOURCE archive pins match the fixture;
                # only the unchanged original receipt/member validators can refuse.
                data = self.retained_fixture(original=original)
                root = Path(temporary)
                with self.selected_context(data, root), self.assertRaises(ValueError):
                    TOOL.restore_selected(root / 'projection', data['target'])
                self.assertFalse((root / 'projection/extracted').exists())

    def test_source_changes_during_copy_and_restore_refuse(self):
        for copy_only in (True, False):
            for original_source in (True, False):
                with self.subTest(copy_only=copy_only, original_source=original_source), tempfile.TemporaryDirectory() as temporary:
                    data = self.retained_fixture()
                    if copy_only:
                        data['nomination']['targets'][data['target']]['transport'] = {'kind': 'original'}
                    def change(source, nomination):
                        path = source if original_source else nomination
                        path.write_bytes(path.read_bytes() + b'\n')
                    root = Path(temporary)
                    with self.selected_context(data, root, during_download=change) as calls, \
                            self.assertRaisesRegex(ValueError, 'SOURCE-selected signed Store'):
                        command = TOOL.retain_selected if copy_only else TOOL.restore_selected
                        command(root / 'output', data['target'])
                    self.assertEqual(len(calls['downloads']), 1)

    def test_explicit_original_routes_remain_bound_to_live_original_artifacts(self):
        for arch in ('arm64', 'x86_64'):
            for expired in (False, True):
                with self.subTest(arch=arch, expired=expired), tempfile.TemporaryDirectory() as temporary:
                    data = self.retained_fixture(arch=arch)
                    artifact_id = 300 if arch == 'arm64' else 301
                    if arch == 'arm64':
                        data['nomination']['targets'][data['target']]['transport'] = {'kind': 'original'}
                    data['responses'][f'actions/artifacts/{artifact_id}']['expired'] = expired
                    root = Path(temporary)
                    with self.selected_context(data, root) as calls:
                        if expired:
                            with self.assertRaises(ValueError): TOOL.restore_selected(root / 'projection', data['target'])
                            self.assertFalse((root / 'projection').exists())
                        else:
                            result = TOOL.restore_selected(root / 'projection', data['target'])
                            self.assertTrue((result / 'bin/ruby').is_file())
                            origin = json.loads((root / 'projection/signed-origin.json').read_bytes())
                            self.assertNotIn('retainedTransport', origin)
                        self.assertNotIn('actions/artifacts/400/zip', calls['downloads'])


if __name__ == '__main__': unittest.main()
