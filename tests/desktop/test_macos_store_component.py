"""Pure artifact-origin and DATA extraction tests; no native/network execution."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

SPEC = importlib.util.spec_from_file_location('store_component_test',
    Path(__file__).resolve().parents[2] / 'desktop/tools/macos_store_component.py')
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)
SOURCE = 'a' * 40


class StoreComponent(unittest.TestCase):
    def origin(self):
        run = {'id': 100, 'repository': {'full_name': TOOL.REPOSITORY},
               'head_repository': {'full_name': TOOL.REPOSITORY}, 'head_branch': TOOL.BRANCH,
               'event': 'push', 'head_sha': SOURCE, 'workflow_id': 20, 'run_attempt': 2,
               'status': 'completed', 'conclusion': 'failure'}
        workflow = {'id': 20, 'path': TOOL.WORKFLOW}
        artifact = {'id': 300, 'name': TOOL.artifact_name('arm64', SOURCE, 1), 'expired': False,
                    'workflow_run': {'id': 100, 'head_sha': SOURCE}, 'size_in_bytes': 100,
                    'digest': 'sha256:' + 'b' * 64}
        jobs = [{'name': 'Native Ruby base (arm64)', 'run_id': 100, 'run_attempt': 1,
                 'head_sha': SOURCE, 'status': 'completed', 'conclusion': 'success'}]
        return run, workflow, artifact, jobs

    def test_original_base_success_not_overall_run_success_authorizes_reuse(self):
        original = self.origin()
        TOOL.validate_origin(*original, run_id=100, source=SOURCE, arch='arm64', attempt=1)
        mutations = [(0, 'event', 'pull_request'), (0, 'head_branch', 'main'),
                     (0, 'head_repository', {'full_name': 'someone/fork'}),
                     (0, 'repository', {'full_name': 'someone/fork'}), (0, 'head_sha', 'c' * 40),
                     (0, 'workflow_id', 21), (1, 'path', 'other.yml'),
                     (2, 'expired', True), (2, 'name', TOOL.artifact_name('x86_64', SOURCE, 1)),
                     (2, 'workflow_run', {'id': 101, 'head_sha': SOURCE}),
                     (2, 'size_in_bytes', TOOL.LIMIT + 1024 * 1024 + 1), (2, 'digest', 'unknown')]
        for index, key, value in mutations:
            with self.subTest(key=key, value=value):
                data = copy.deepcopy(original); data[index][key] = value
                with self.assertRaises(ValueError):
                    TOOL.validate_origin(*data, run_id=100, source=SOURCE, arch='arm64', attempt=1)
        for key, value in [('conclusion', 'failure'), ('status', 'in_progress'),
                           ('run_attempt', 2), ('name', 'Native Ruby base (x86_64)'),
                           ('head_sha', 'd' * 40), ('run_id', 101)]:
            data = copy.deepcopy(original); data[3][0][key] = value
            with self.assertRaises(ValueError):
                TOOL.validate_origin(*data, run_id=100, source=SOURCE, arch='arm64', attempt=1)
        for jobs in ([], original[3] * 2):
            with self.assertRaises(ValueError):
                TOOL.validate_origin(*original[:3], jobs, run_id=100, source=SOURCE, arch='arm64', attempt=1)

    def fixture(self, root):
        base = root / 'base'; (base / 'bin').mkdir(parents=True)
        ruby = base / 'bin/ruby'; ruby.write_bytes(b'nonexecutable synthetic Ruby fixture'); ruby.chmod(0o755)
        (base / 'licenses').mkdir(); (base / 'licenses/test').write_text('retain')
        output = root / 'artifact'
        with mock.patch.object(TOOL, 'toolchain_facts', return_value={'sdk': '26.0', 'clang': 'synthetic clang'}):
            TOOL.archive_base(base, output, SOURCE, 'arm64', 100, 1)
        return base, output

    def test_archive_roundtrip_and_exclusive_ordinary_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); base, artifact = self.fixture(root)
            result = TOOL.extract_base(artifact / 'ruby-base.tar.gz', root / 'result')
            self.assertEqual((result / 'bin/ruby').read_bytes(), (base / 'bin/ruby').read_bytes())
            self.assertEqual((result / 'bin/ruby').stat().st_mode & 0o777, 0o755)
            self.assertEqual((result / 'licenses/test').read_text(), 'retain')
            with self.assertRaises(FileExistsError):
                TOOL.extract_base(artifact / 'ruby-base.tar.gz', root / 'result')
            with self.assertRaises(FileExistsError):
                TOOL.archive_base(base, artifact, SOURCE, 'arm64', 100, 1)
            (base / 'linked').symlink_to('bin/ruby')
            with self.assertRaises(ValueError):
                TOOL.archive_base(base, root / 'bad-artifact', SOURCE, 'arm64', 100, 1)

    def test_traversal_duplicate_link_and_expansion_refuse(self):
        for case in ('traversal', 'duplicate', 'link', 'size'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); archive = root / 'bad.tar.gz'
                with tarfile.open(archive, 'w:gz') as output:
                    row = tarfile.TarInfo('ruby-base/../../escaped' if case == 'traversal' else 'ruby-base/bin/ruby')
                    row.size = 1
                    if case == 'link': row.type = tarfile.SYMTYPE; row.linkname = '/outside'; row.size = 0
                    output.addfile(row, io.BytesIO(b'x'))
                    if case == 'duplicate': output.addfile(row, io.BytesIO(b'x'))
                with mock.patch.object(TOOL, 'LIMIT', 0 if case == 'size' else TOOL.LIMIT):
                    with self.assertRaises((ValueError, tarfile.FilterError)):
                        TOOL.extract_base(archive, root / 'output')
                self.assertFalse((root / 'escaped').exists())

    def test_restore_uses_original_attempt_and_service_digest_then_preserves_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); _base, artifact_dir = self.fixture(root)
            transport = io.BytesIO()
            with zipfile.ZipFile(transport, 'w') as target:
                for path in sorted(artifact_dir.iterdir()): target.writestr(path.name, path.read_bytes())
            payload = transport.getvalue()
            run, workflow, artifact, jobs = self.origin()
            artifact.update(size_in_bytes=len(payload), digest='sha256:' + hashlib.sha256(payload).hexdigest())
            responses = {'actions/runs/100': run,
                         'actions/workflows/desktop-macos-store-runtime.yml': workflow,
                         'actions/runs/100/artifacts?per_page=100': {'total_count': 1, 'artifacts': [artifact]},
                         'actions/artifacts/300': artifact,
                         'actions/runs/100/attempts/1/jobs?per_page=100': {'total_count': 1, 'jobs': jobs}}
            def download(argv, *, stdout, check, timeout):
                self.assertEqual(argv, ['gh', 'api', f'repos/{TOOL.REPOSITORY}/actions/artifacts/300/zip'])
                self.assertEqual(timeout, 180); stdout.write(payload)
            with mock.patch.object(TOOL, 'api', side_effect=lambda path: responses[path]), \
                    mock.patch.object(TOOL.subprocess, 'run', side_effect=download) as called:
                # Current run attempt2 has no new base: reuse exact unique attempt1.
                result = TOOL.restore(root / 'restored', 100, SOURCE, 'arm64')
                self.assertTrue((result / 'bin/ruby').is_file())
                origin = json.loads((root / 'restored/base.json').read_text())
                self.assertEqual((origin['source'], origin['runAttempt'], origin['artifactId']), (SOURCE, 1, 300))
                self.assertFalse((root / 'restored/artifact.zip').exists())
                self.assertEqual(called.call_count, 1)
                with mock.patch.object(TOOL, 'native_inputs', return_value={'recipe': 'changed'}):
                    with self.assertRaises(ValueError):
                        TOOL.restore(root / 'changed-native-input', 100, SOURCE, 'arm64', 300)
                self.assertFalse((root / 'changed-native-input/extracted').exists())
                artifact['digest'] = 'sha256:' + 'f' * 64
                with self.assertRaises(ValueError):
                    TOOL.restore(root / 'bad-digest', 100, SOURCE, 'arm64', 300)
                self.assertFalse((root / 'bad-digest/extracted').exists())
                artifact['expired'] = True
                with self.assertRaises(ValueError):
                    TOOL.restore(root / 'expired', 100, SOURCE, 'arm64', 300)
                self.assertEqual(called.call_count, 3)  # Metadata refusal before download.


if __name__ == '__main__': unittest.main()
