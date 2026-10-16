"""Service/native facts are inert DATA; no downloaded/native code runs here."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
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
            'outerExitRequired': True, 'nativeCallCount': 374, 'credentialCallCount': 19,
            'credentialContexts': [{'purpose': FIXTURE.M.PHASE, 'closed': True, 'retired': True,
                                   'searchRestored': True, 'defaultUnchanged': True}],
            'signedArchiveSha256': hashlib.sha256(archive).hexdigest(), 'signedArchiveBytes': len(archive),
            'signedInventorySha256': FIXTURE.M.sha(FIXTURE.M.canonical(rows)),
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

    def attempt(self, root, arch, fixture):
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
            return TOOL.restore_signed(root, 100, SOURCE, arch, 300)

    def test_exact_architecture_complete_roster_and_service_project_without_execution(self):
        for arch in ('arm64', 'x86_64'):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / 'projection'
                fixture = self.fixture(arch)
                result = self.attempt(root, arch, fixture)
                self.assertEqual((result / 'licenses/NOTICE').read_bytes(), b'Keep every original notice byte\n')
                self.assertEqual(len([p for p in result.rglob('*') if p.is_file()]), 189)
                self.assertEqual(json.loads((root / 'signed-origin.json').read_bytes())['artifactId'], 300)
                self.assertFalse((root / 'artifact.zip').exists())
                with self.assertRaises(FileExistsError): self.attempt(root, arch, fixture)

    def test_wrong_origin_incomplete_closure_signer_or_full_inventory_refuse(self):
        fixture = self.fixture('arm64')
        changes = ('job', 'branch', 'source', 'calls', 'closure', 'identity', 'inventory', 'native', 'native-duplicate')
        for changed in changes:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                data = copy.deepcopy(fixture)
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


if __name__ == '__main__': unittest.main()
