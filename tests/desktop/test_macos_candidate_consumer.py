"""Candidate owner adapter DATA/call-seam tests; never native or network tests.

Authored detached. Run only after the parent explicitly authorizes a focused
networkless test invocation; no workflow/carrier/native qualification follows.
"""
from collections import namedtuple
from contextlib import ExitStack
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock
import sys
import stat

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from desktop.tools import macos_candidate_consumer as C
from desktop.tools import macos_fixed_carrier_resume as R


def nomination(target='aarch64-apple-darwin'):
    return dict(source='1' * 40, tree='2' * 40, target=target, runId='42', runAttempt='2',
                jobId='43', artifactId='44', artifactBytes=100, artifactSha256='3' * 64)


def instance(target='aarch64-apple-darwin'):
    # Only suppress directory acquisition for this DATA constructor test.
    with mock.patch.object(R.Resume, '__init__', return_value=None):
        return C.CandidateResume(C.HELPER_ROOT, C.CANDIDATE_ROOT, Path('/inert'), None, None,
                                 nomination=nomination(target))


def mounted_fixture(target):
    """Parser seam supplies already-parsed inert structures, not fake XAR proof."""
    bodies = {'Install.pkg': b'package', 'producer.json': b'descriptor', 'producer.sig': b'signature'}
    row = nomination(target)
    architecture = 'arm64' if target == 'aarch64-apple-darwin' else 'x86_64'
    row.update(packageVersion='0.1.9', release='macos26-'+architecture+'-current-source-release',
               runtimeManifestSha256='a' * 64, inventorySha256=R.sha(b'inventory'),
               members=[dict(name=name, bytes=7, sha256=R.sha(name.encode())) for name in sorted(R.CANDIDATE_MEMBERS)],
               signingIdentity={'teamIdentifier': 'INERTTEAM0'})
    for key, name in (('package', 'Install.pkg'), ('descriptor', 'producer.json'), ('signature', 'producer.sig')):
        row[key] = dict(name=name, bytes=len(bodies[name]), sha256=R.sha(bodies[name]))
    release = dict(profile='fixed-macos26-'+architecture+'-maintenance-v2',
                   packageIdentifier='dev.mobile-release-kit.desktop.installed', bundleIdentifier='dev.mobile-release-kit.desktop',
                   protocolSha256='c'*64, sourceCommit=row['source'], runtimeManifestSha256=row['runtimeManifestSha256'],
                   inventorySha256=row['inventorySha256'], packageVersion=row['packageVersion'],
                   release=row['release'], packageSha256=row['package']['sha256'], signingPolicySha256='b' * 64)
    policy = {'sha256': 'b' * 64, 'policy': dict(row['signingIdentity'])}
    selection_type = namedtuple('BuildSelection', 'target package_version release')
    selection = selection_type(target, row['packageVersion'], row['release'])
    stage = SimpleNamespace(BuildSelection=selection_type, INSTALL_COMPONENT='component',
        INSTALLATION_INVENTORY_NAME='install-inventory.json', INVENTORY_BYTES=12 << 20,
        distribution_layout_data=mock.Mock(),
        maintenance_producer_data=mock.Mock(return_value={
            'releaseSet': {'current': release, 'acceptedPredecessors': []}, 'signingPolicies': [policy]}),
        source_build_selection=mock.Mock(return_value=selection),
        install_product_members=mock.Mock(return_value={'component/PackageInfo': b'info', 'component/Scripts': b'cpio'}),
        package_info=mock.Mock(), cpio_members=mock.Mock(return_value={'input/install-inventory.json': (b'inventory', 0o444)}),
        observation_inventory_bytes=mock.Mock(return_value={'runtime/file': {'size': 5}}),
        decode=mock.Mock(return_value={'inert': True}))
    return {name: (body, 0o444) for name, body in bodies.items()}, row, stage


class CandidateConsumerTests(unittest.TestCase):
    def test_immutable_selection_default_owner_and_arch_transport_separation(self):
        legacy = object.__new__(R.Resume)
        self.assertIs(legacy.origin, R.ORIGIN)
        self.assertEqual(legacy.target, 'aarch64-apple-darwin')
        self.assertEqual(legacy.image_name, 'arm64.dmg')
        paths = set()
        for target, name in (('aarch64-apple-darwin', 'arm64.dmg'), ('x86_64-apple-darwin', 'intel.dmg')):
            row = nomination(target)
            with mock.patch.object(R.Resume, '__init__', return_value=None):
                owner = C.CandidateResume(C.HELPER_ROOT, C.CANDIDATE_ROOT, Path('/inert'), None, None, nomination=row)
            row['source'] = 'f' * 40
            exposed = owner.nomination; exposed['target'] = 'other'
            self.assertEqual(owner.nomination['source'], '1' * 40)
            self.assertEqual(owner.target, target)
            self.assertEqual(owner.image_name, name)
            with self.assertRaises(ValueError): _ = owner.origin
            owner.run_id, owner.run_attempt = '51', '2'
            paths.add(owner.mount_path())
            self.assertNotEqual(owner.mount_path(), R.transport_path_data('51', '2'))
        self.assertEqual(len(paths), 2)
        with mock.patch.object(R.Resume, '__init__', return_value=None):
            with self.assertRaises(ValueError):
                C.CandidateResume(C.CANDIDATE_ROOT, C.CANDIDATE_ROOT, Path('/inert'), None, None, nomination=nomination())

    def test_dynamic_resource_bounds_never_borrow_legacy_carrier_sizes(self):
        for target in ('aarch64-apple-darwin', 'x86_64-apple-darwin'):
            row = nomination(target)
            before = C.candidate_resource_requirements(row, 4096, 2048)
            after = C.candidate_resource_requirements(row, 4096, 2048, image_bytes=17)
            self.assertEqual(before['acquisitionMemory'] - after['acquisitionMemory'], 6 * (R.LIMIT - 17))
            self.assertEqual(after['acquisitionMemory'] - after['postAcquisitionMemory'], 6 * row['artifactBytes'])
            self.assertEqual(after['requiredDisk'], (3 << 30) + 2 * row['artifactBytes'] + 34 + 2048)
            larger = C.candidate_resource_requirements(dict(row, artifactBytes=R.LIMIT), 4096, 2048, image_bytes=17)
            self.assertEqual(larger['acquisitionMemory'] - after['acquisitionMemory'], 6 * (R.LIMIT - row['artifactBytes']))
        for retained, host, image in ((True, 0, None), (0, -1, None), (0, 0, True), (0, 0, R.LIMIT + 1)):
            with self.assertRaises(ValueError): C.candidate_resource_requirements(nomination(), retained, host, image_bytes=image)

    def test_child_source_limits_precede_construction_and_sources_are_explicit(self):
        bodies = {name: (ROOT / name).read_bytes() for name in (C.LEGACY_PATH, C.PARSER_PATH)}
        self.assertLessEqual(len(bodies[C.LEGACY_PATH]), 164 << 10)
        source = C.acquisition_bootstrap(C.HELPER_ROOT, bodies)
        self.assertLessEqual(len(source.encode()), C.CHILD_SOURCE_LIMIT)
        # Compile is syntax-only; do not exec the child or make an API request.
        compile(source, '<inert-candidate-bootstrap>', 'exec')
        for changed in ({C.LEGACY_PATH: b'x' * ((164 << 10) + 1), C.PARSER_PATH: b'x'},
                        {C.LEGACY_PATH: b'\x00' * (164 << 10), C.PARSER_PATH: b'x'},
                        {C.LEGACY_PATH: b'x'}):
            with self.assertRaises(ValueError): C.acquisition_bootstrap(C.HELPER_ROOT, changed)
        with self.assertRaises(ValueError): C.acquisition_bootstrap(C.CANDIDATE_ROOT, bodies)

    def test_actual_shared_mounted_guard_uses_current_source_and_scoped_store_parser(self):
        for target in ('aarch64-apple-darwin', 'x86_64-apple-darwin'):
            originals, row, stage = mounted_fixture(target)
            result, inventory = R.mounted_data(originals, row, target, stage, candidate=True)
            self.assertEqual(inventory, b'inventory')
            self.assertEqual(result['kind'], 'mrk-candidate-mounted-data-v1')
            self.assertNotIn('qualificationEvidenceSha256', result)
            self.assertFalse(result['nativeQualificationInferred'])
            stage.source_build_selection.assert_called_once_with(target)
            stage.cpio_members.assert_called_once_with(b'cpio', store_runtime=True)
            stage.decode.assert_called_once_with(b'inventory', byte_limit=12 << 20, node_limit=150000)
            for key in ('source', 'release', 'runtimeManifestSha256'):
                invalid = dict(row, **{key: 'changed'})
                with self.subTest(target=target, key=key), self.assertRaises(ValueError):
                    R.mounted_data(originals, invalid, target, stage, candidate=True)
            originals, row, stage = mounted_fixture(target)
            stage.source_build_selection.return_value = stage.BuildSelection(target, '0.1.0', row['release'])
            with self.assertRaises(ValueError): R.mounted_data(originals, row, target, stage, candidate=True)
            stage.install_product_members.assert_not_called()

    def test_public_predecessor_projection_keeps_real_mounted_bindings_without_payload(self):
        for target in ('aarch64-apple-darwin', 'x86_64-apple-darwin'):
            originals, row, stage = mounted_fixture(target)
            # Actual shared reducer; lower archive/native boundaries are inert,
            # not fabricated native signature or filesystem qualification.
            result, inventory = R.mounted_data(originals, row, target, stage, candidate=True)
            raw = C.predecessor_metadata_projection(result, nomination(target))
            value = R.decode(raw)
            self.assertIs(C.predecessor_metadata_data(value, nomination(target)), value)
            self.assertEqual(value['inventory']['sha256'], R.sha(inventory))
            self.assertEqual(value['release'], result['release'])
            self.assertEqual(value['members'], row['members'])
            self.assertLessEqual(len(raw), C.PREDECESSOR_METADATA_LIMIT)
            for excluded in ('inventoryDocument', 'signingPolicy', 'policy', 'qualificationEvidenceSha256'):
                self.assertNotIn(excluded, value)
            self.assertNotIn(b'INERTTEAM0', raw)
            self.assertFalse(value['nativeQualificationInferred'] or value['updateActivated'])
            changes = [lambda v: v['nomination'].update(source='f'*40),
                lambda v: v['package'].update(sha256='f'*64),
                lambda v: v['inventory'].update(sha256='f'*64),
                lambda v: v['release'].update(sourceCommit='f'*40),
                lambda v: v['release'].update(packageVersion='1.02.3'),
                lambda v: v['members'].append(v['members'][0]),
                lambda v: v['members'][0].update(name='../private'),
                lambda v: v.update(inventoryFiles=True),
                lambda v: v.update(nativeQualificationInferred=True),
                lambda v: v.update(inventoryDocument={'private': 'must never publish'})]
            for change in changes:
                wrong = copy.deepcopy(value); change(wrong)
                with self.assertRaises(ValueError): C.predecessor_metadata_data(wrong, nomination(target))

    def test_public_predecessor_receipt_requires_actual_consume_finality(self):
        originals, row, stage = mounted_fixture('aarch64-apple-darwin')
        result, inventory = R.mounted_data(originals, row, row['target'], stage, candidate=True)
        for fault in (None, 'installer', 'readback', 'mount', 'call', 'close', 'post-source'):
            with self.subTest(fault=fault):
                owner = instance()
                owner._CandidateResume__source_loaded = True
                owner.helper_source, owner.helper_tree, owner.run_id, owner.run_attempt = 'd'*40, 'e'*40, '51', '2'
                owner.quota = SimpleNamespace(reserved=0, finish=mock.Mock(return_value=fault != 'close'))
                owner.clock = SimpleNamespace(finality=False, check=mock.Mock())
                owner.point = mock.Mock(); owner.admit_resources = mock.Mock(); owner.retire = mock.Mock()
                owner.acquire_candidate = mock.Mock(return_value={'PREVIEW.json': b'inert', 'MobileReleaseKit.dmg': b'inert'})
                owner.verify_sources = mock.Mock(side_effect=[None, RuntimeError('original source POST')] if fault == 'post-source' else None)
                owner.installer_zero = owner.readback_known = owner.mount_detached = False
                owner.calls = [{'returned': True, 'capturesSettled': fault != 'call'}]
                def install(*args):
                    owner.prepare_readback(result, inventory)
                    if fault == 'installer': raise RuntimeError('original Installer failure')
                    owner.installer_zero = True
                    if fault == 'readback': raise RuntimeError('original readback failure')
                    owner.readback_known = True; owner.mount_detached = fault != 'mount'
                owner.install_image = install
                with mock.patch.object(C.candidate, 'candidate_preview_data', return_value={}):
                    if fault is None:
                        observed = owner.consume(0, 0)
                        self.assertEqual(observed['predecessorMetadata'], R.decode(C.predecessor_metadata_projection(result, owner.nomination)))
                        self.assertFalse(observed['p0Qualified'] or observed['productReady'])
                        self.assertLessEqual(len(R.canonical(observed)), C.PREDECESSOR_METADATA_LIMIT)
                    else:
                        with self.assertRaises((RuntimeError, ValueError)): owner.consume(0, 0)
                self.assertGreaterEqual(owner.quota.finish.call_count, 1)

    def test_legacy_mounted_default_never_enables_store_or_source_override(self):
        originals, row, stage = mounted_fixture('aarch64-apple-darwin')
        row['qualificationEvidenceSha256'] = 'c' * 64
        result, _ = R.mounted_data(originals, row, row['target'], stage)
        self.assertEqual(result['kind'], 'mrk-p0-readonly-enrollment-data-v1')
        self.assertEqual(result['qualificationEvidenceSha256'], 'c' * 64)
        stage.source_build_selection.assert_not_called()
        stage.cpio_members.assert_called_once_with(b'cpio')
        stage.decode.assert_called_once_with(b'inventory')
        with self.assertRaises(ValueError): R.mounted_data(originals, row, row['target'], stage, candidate=1)

    def test_ordinary_readback_no_fixed_release_override_and_fresh_only(self):
        owner = instance('x86_64-apple-darwin')
        owner.selection = ('source-selected',)
        response = {'originalInstallerResult': {'action': 'fresh-install'}, 'installationMetadata': [{}]}
        owner.stager = SimpleNamespace(source_build_selection=mock.Mock(return_value=owner.selection),
                                       observation_command=mock.Mock(return_value=response))
        args = SimpleNamespace(target=owner.target)
        with mock.patch.object(R, 'original_release_readback_data', side_effect=AssertionError('legacy route entered')):
            originals, row, stage = mounted_fixture(owner.target)
            result, inventory = R.mounted_data(originals, row, owner.target, stage, candidate=True)
            self.assertIsNone(owner.prepare_readback(result, inventory))
            self.assertIs(owner.observe_installation(args, None), response)
        owner.stager.observation_command.assert_called_once_with(args)
        for action, generations in (('same-package-noop', [{}]), ('update', [{}]), ('fresh-install', [{}, {}])):
            response['originalInstallerResult']['action'] = action
            response['installationMetadata'] = generations
            with self.assertRaises(ValueError): owner.observe_installation(args, None)
        with self.assertRaises(ValueError): owner.observe_installation(args, {'legacy': 'forbidden'})

    def test_legacy_readback_refusal_is_still_before_input_and_installer(self):
        # Exercise the actual shared native-owner method with inert filesystem
        # and native-call boundaries. The original legacy DATA guard is real.
        image = b'inert-image'
        message = R.producer_message_data(b'inert-descriptor')
        info = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFDIR | 0o555,
                               st_uid=0, st_gid=0, st_nlink=1, st_size=0, st_mtime_ns=0, st_ctime_ns=0)
        directory = {'fd': -1, 'identity': R.identity(info)}
        outer = SimpleNamespace(directories={Path('/'): directory},
                                read=lambda entry: image if entry['path'].suffix == '.dmg' else message)
        mounted = SimpleNamespace(check=lambda: None, finish=lambda: True)
        def quote(book, operation, path, *args, **kwargs):
            if operation == 'directory': return directory
            return {'identity': (1, 2), 'path': path}, image if path.suffix == '.dmg' else message
        calls = []
        def command(role, argv, timeout):
            calls.append(role)
            body = (b'-----BEGIN PUBLIC KEY-----\ninert\n-----END PUBLIC KEY-----\n'
                    if role == 'producer-key' else b'Verified OK\n' if role == 'producer-signature' else b'')
            return SimpleNamespace(returncode=0, stdout=body, stderr=b'')
        owner = SimpleNamespace(work=Path('/inert'), root=Path('/helper'), image_name='arm64.dmg',
            target='aarch64-apple-darwin', publish_image=mock.Mock(), outer=outer, private={},
            quota=SimpleNamespace(call=quote), mount_path=lambda: Path('/Volumes/inert'),
            transport_facts=lambda entry: 'same', transport_roster=lambda entry: ({}, 'same'),
            command=command, fresh_book=lambda **kw: mounted, point=lambda: None,
            host=SimpleNamespace(filesystem=lambda fd: {'flags': 0}), publish_owned=mock.Mock(),
            read_mounted=lambda *args: ({'producer.json': (b'inert-descriptor', 0o444)}, {}, {}, b'inventory'),
            stager=SimpleNamespace(distribution_mount_data=lambda *args: '/dev/inert'),
            fresh_directory=mock.Mock(side_effect=AssertionError('input published before guard')),
            clock=SimpleNamespace(finality=False))
        owner.prepare_readback = lambda result, inventory: R.Resume.prepare_readback(owner, result, inventory)
        with ExitStack() as patches:
            patches.enter_context(mock.patch.object(R.os, 'fstat', return_value=info))
            patches.enter_context(mock.patch.object(R.os, 'stat', return_value=info))
            patches.enter_context(mock.patch.object(R.os, 'fstatvfs', return_value=SimpleNamespace(f_flag=0)))
            patches.enter_context(mock.patch.object(R.os, 'listdir', return_value=['Install.pkg', 'producer.json', 'producer.sig']))
            patches.enter_context(mock.patch.object(R, 'mount_data'))
            patches.enter_context(mock.patch.object(R, 'transport_transition_data'))
            with self.assertRaisesRegex(ValueError, 'resume-original-release-provenance'):
                R.Resume.install_image(owner, image, {})
        self.assertEqual(calls, ['attach', 'producer-key', 'producer-signature', 'detach'])
        self.assertFalse(owner.installer_entered)
        self.assertTrue(owner.mount_detached)
        owner.fresh_directory.assert_not_called()

    def test_acquire_only_shared_native_owner_detaches_before_input_and_refuses_unknown_close(self):
        # Same actual native method, no process/transport execution in this fixture.
        image = b'inert-image'
        message = R.producer_message_data(b'inert-descriptor')
        info = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFDIR | 0o555,
                               st_uid=0, st_gid=0, st_nlink=1, st_size=0, st_mtime_ns=0, st_ctime_ns=0)
        directory = {'fd': -1, 'identity': R.identity(info)}
        outer = SimpleNamespace(directories={Path('/'): directory},
                                read=lambda entry: image if entry['path'].suffix == '.dmg' else message)
        mounted = SimpleNamespace(check=lambda: None, finish=mock.Mock(return_value=True))
        def quote(book, operation, path, *args, **kwargs):
            if operation == 'directory': return directory
            return {'identity': (1, 2), 'path': path}, image if path.suffix == '.dmg' else message
        calls = []
        def command(role, argv, timeout):
            calls.append(role)
            body = (b'-----BEGIN PUBLIC KEY-----\ninert\n-----END PUBLIC KEY-----\n'
                    if role == 'producer-key' else b'Verified OK\n' if role == 'producer-signature' else b'')
            return SimpleNamespace(returncode=0, stdout=body, stderr=b'')
        owner = SimpleNamespace(work=Path('/inert'), root=Path('/helper'), image_name='arm64.dmg',
            target='aarch64-apple-darwin', publish_image=mock.Mock(), outer=outer, private={},
            quota=SimpleNamespace(call=quote), mount_path=lambda: Path('/Volumes/inert'),
            transport_facts=lambda entry: 'same', transport_roster=lambda entry: ({}, 'same'),
            command=command, fresh_book=lambda **kw: mounted, point=lambda: None,
            host=SimpleNamespace(filesystem=lambda fd: {'flags': 0}), publish_owned=mock.Mock(),
            read_mounted=lambda *args: ({'producer.json': (b'inert-descriptor', 0o444)}, {},
                dict(package={'sha256':'1'*64},descriptor={'sha256':'2'*64},signature={'sha256':'3'*64},
                    inventory={'sha256':'4'*64},release={'runtimeManifestSha256':'5'*64}), b'inventory'),
            stager=SimpleNamespace(distribution_mount_data=lambda *args: '/dev/inert'),
            fresh_directory=mock.Mock(side_effect=AssertionError('input published before guard')),
            clock=SimpleNamespace(finality=False))
        owner.purpose = 'acquire'
        owner.prepare_readback = mock.Mock(side_effect=lambda result, inventory: C.CandidateResume.prepare_readback(owner, result, inventory))
        with ExitStack() as patches:
            patches.enter_context(mock.patch.object(R.os, 'fstat', return_value=info))
            patches.enter_context(mock.patch.object(R.os, 'stat', return_value=info))
            patches.enter_context(mock.patch.object(R.os, 'fstatvfs', return_value=SimpleNamespace(f_flag=0)))
            patches.enter_context(mock.patch.object(R.os, 'listdir', return_value=['Install.pkg', 'producer.json', 'producer.sig']))
            patches.enter_context(mock.patch.object(R, 'mount_data'))
            patches.enter_context(mock.patch.object(R, 'transport_transition_data'))
            R.Resume.install_image(owner, image, {})
            self.assertEqual(owner.acquisition_result['runtimeManifestSha256'],'5'*64)
            self.assertEqual(calls, ['attach','producer-key','producer-signature','detach'])
            self.assertTrue(owner.mount_detached)
            calls.clear(); mounted.finish.return_value=False
            with self.assertRaisesRegex(ValueError, 'resume-mounted-close-unknown'):
                R.Resume.install_image(owner,image,{})
            mounted.finish.return_value = True
            for fault in ('signature', 'mounted-post'):
                calls.clear(); owner.prepare_readback.reset_mock()
                def refused_command(role, argv, timeout):
                    observed = command(role, argv, timeout)
                    if fault == 'signature' and role == 'producer-signature': observed.returncode = 1
                    return observed
                def checked():
                    if fault == 'mounted-post' and calls and calls[-1] == 'producer-signature':
                        raise RuntimeError('original mounted signature POST')
                owner.command = refused_command; mounted.check = checked
                with self.assertRaises((ValueError, RuntimeError)):
                    R.Resume.install_image(owner, image, {})
                owner.prepare_readback.assert_not_called()
        self.assertEqual(calls, ['attach', 'producer-key', 'producer-signature', 'detach'])
        self.assertFalse(owner.installer_entered)
        owner.fresh_directory.assert_not_called()

    def test_consume_preserves_failure_finality_and_entry_remains_closed(self):
        for close_known in (True, False):
            owner = instance()
            owner._CandidateResume__source_loaded = True
            owner.quota = SimpleNamespace(finish=mock.Mock(return_value=close_known), reserved=0)
            owner.admit_resources = mock.Mock()
            failure = RuntimeError('inert-original-acquisition-failed')
            owner.acquire_candidate = mock.Mock(side_effect=failure)
            owner.install_image = mock.Mock(); owner.retire = mock.Mock()
            with self.assertRaises(RuntimeError) as caught: owner.consume(0, 0)
            self.assertIs(caught.exception, failure)
            owner.quota.finish.assert_called_once_with()
            owner.install_image.assert_not_called(); owner.retire.assert_not_called()
            if not close_known: self.assertIn('candidate-original-final-closes', caught.exception.__notes__)
        with mock.patch.dict(C.os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'candidate-target'): C.main()

    def test_context_and_fixed_source_selection_are_independent_of_carrier_claims(self):
        import json
        for target, machine, arch in (('aarch64-apple-darwin', 'arm64', 'ARM64'), ('x86_64-apple-darwin', 'x86_64', 'X64')):
            env = dict(MRK_MACOS_TARGET=target, GITHUB_WORKSPACE=str(C.CANDIDATE_ROOT), RUNNER_TEMP='/Users/runner/work/_temp',
                GITHUB_REPOSITORY=R.REPOSITORY, GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/' + C.BRANCH,
                GITHUB_WORKFLOW_REF=R.REPOSITORY + '/' + C.WORKFLOW + '@refs/heads/' + C.BRANCH,
                GITHUB_SHA='d' * 40, GITHUB_WORKFLOW_SHA='d' * 40, RUNNER_OS='macOS', RUNNER_ARCH=arch,
                RUNNER_ENVIRONMENT='github-hosted', GITHUB_RUN_ID='51', GITHUB_RUN_ATTEMPT='2',
                MRK_MACOS_WORK='/Users/runner/work/_temp/mrk-macos-installed.ABCDEFGH')
            context = C.context_data(env, C.HELPER_ROOT, machine)
            self.assertEqual(context['target'], target)
            self.assertEqual(context['helperSource'], 'd' * 40)
            for key, value in (('GITHUB_SHA', '1' * 40), ('GITHUB_EVENT_NAME', 'workflow_dispatch'),
                               ('RUNNER_ARCH', 'other'), ('GITHUB_WORKSPACE', str(C.HELPER_ROOT)),
                               ('GITHUB_REF', 'refs/heads/main'), ('MRK_MACOS_WORK', '/tmp/user-work')):
                with self.subTest(target=target, key=key), self.assertRaises(ValueError):
                    C.context_data(dict(env, **{key: value}), C.HELPER_ROOT, machine)
            value = {'schemaVersion': 1, 'targets': {key: nomination(key) for key in ('aarch64-apple-darwin', 'x86_64-apple-darwin')}}
            self.assertEqual(C.selection_data(json.dumps(value).encode(), target), nomination(target))
            value['targets'][target]['target'] = 'other'
            with self.assertRaises(ValueError): C.selection_data(json.dumps(value).encode(), target)

    def test_failure_locations_do_not_export_private_exception_data(self):
        from types import FunctionType
        private = 'PRIVATE-SYNTHETIC-TEXT-NOT-FOR-LOGS'
        try:
            C.context_data({'MRK_MACOS_TARGET': 'aarch64-apple-darwin'}, C.HELPER_ROOT, 'arm64')
        except R.Refused as error:
            value = C.failure_data(error)
        else:
            self.fail('expected actual context refusal')
        self.assertEqual(value['reason'], 'candidate-hosted-context')
        self.assertEqual(value['exceptionClass'], 'Refused')
        self.assertTrue(any(row['file'] == 'macos_candidate_consumer.py' and row['function'] == 'context_data'
                            for row in value['sourceFrames']))
        self.assertFalse(value['rawOutputExported'] or value['cleanupAuthorized'])
        self.assertLessEqual(len(value['sourceFrames']), 8)
        class PrivateError(ValueError):
            def __str__(self):
                raise AssertionError('exception text must not be requested')
        for error in (R.Refused(private), ValueError(private), PrivateError(private)):
            value = C.failure_data(error)
            self.assertEqual(value['reason'], 'unavailable')
            self.assertEqual(value['sourceFrames'], [])
            self.assertNotIn(private, R.canonical(value).decode())
            if type(error) is PrivateError:
                self.assertEqual(value['exceptionClass'], 'other')
        # A trusted filename with foreign globals, and trusted globals with a
        # foreign filename, must both be excluded. These tiny functions only raise.
        for path, namespace in ((C.__file__, {}), ('/private/' + private, vars(C))):
            code = compile('def synthetic_private_frame():\n    raise ValueError("' + private + '")\n', path, 'exec')
            function = FunctionType(next(item for item in code.co_consts if hasattr(item, 'co_code')), namespace)
            try:
                function()
            except ValueError as error:
                value = C.failure_data(error)
            self.assertEqual(value['sourceFrames'], [])
            self.assertNotIn(private, R.canonical(value).decode())
        # Repeated real trusted frames stay bounded without traversing arbitrary
        # cause/context chains or reading locals.
        try:
            C.context_data({'MRK_MACOS_TARGET': 'aarch64-apple-darwin'}, C.HELPER_ROOT, 'arm64')
        except R.Refused as error:
            from types import TracebackType
            original = error.__traceback__.tb_next
            repeated = None
            for _ in range(64):
                repeated = TracebackType(repeated, original.tb_frame, original.tb_lasti, original.tb_lineno)
            error.__traceback__ = repeated
            value = C.failure_data(error)
        self.assertEqual(len(value['sourceFrames']), 8)
        self.assertTrue(all(set(row) == {'file', 'function', 'line'} and row['line'] > 0
                            and '/' not in row['file'] for row in value['sourceFrames']))

    def test_system_tool_original_failures_keep_bound_donor_labels_and_errno(self):
        import errno
        import os
        import tempfile
        from types import FunctionType
        private = 'PRIVATE-SYNTHETIC-NEVER-EXPORTED'
        old_module = sys.modules.pop('_mrk_p0_originals', None)
        previous = C._SYSTEM_TOOL_FAILURE
        try:
            donor = R.load_module('_mrk_p0_originals', ROOT / 'desktop/tools/macos_e2_native_fixture.py',
                (ROOT / 'desktop/tools/macos_e2_native_fixture.py').read_bytes())
            with tempfile.TemporaryDirectory() as name, mock.patch.object(C, 'HELPER_ROOT', ROOT):
                path = Path(name) / 'tool'; path.write_bytes(b'inert tool data'); path.chmod(0o600)
                originals = []
                for missing in (False, True):
                    book = donor.Originals()
                    try:
                        book.file(path.with_name('missing') if missing else path, 1024, modes=(0o755,))
                    except (donor.Refused, FileNotFoundError) as error:
                        original = error
                    else:
                        self.fail('expected actual donor refusal')
                    finally:
                        self.assertTrue(book.finish())
                    quota = SimpleNamespace(call=mock.Mock(side_effect=original))
                    session = SimpleNamespace(outer=book, quota=quota)
                    with mock.patch.object(C.os, 'stat', return_value=SimpleNamespace(st_uid=0)):
                        try: C._admit_system_tool(session, 'git', '/usr/bin/git')
                        except BaseException as raised: self.assertIs(raised, original)
                        else: self.fail('original failure was swallowed')
                    quota.call.assert_called_once_with(book, 'file', Path('/usr/bin/git'), 64 << 20,
                        uid=0, modes=(0o555, 0o755, 0o4555, 0o4755), system_tool=True)
                    value = C.failure_data(original)
                    self.assertEqual(value['reason'], 'unavailable' if missing else 'file-original-policy')
                    self.assertEqual(value['exceptionClass'], 'FileNotFoundError' if missing else 'Refused')
                    self.assertEqual(value['systemTool'], {'role': 'git', 'errno': errno.ENOENT if missing else None})
                    self.assertTrue(any(row['file'] == 'macos_e2_native_fixture.py' for row in value['sourceFrames']))
                    self.assertNotIn(name, R.canonical(value).decode())
                    originals.append(original)

                C._SYSTEM_TOOL_FAILURE = (originals[1], 'git', donor.Originals)
                for bad_errno in (True, -1, 65536, private):
                    originals[1].errno = bad_errno
                    value = C.failure_data(originals[1])
                    self.assertEqual(value['systemTool'], {'role': 'git', 'errno': None})
                    self.assertNotIn(private, R.canonical(value).decode())
                originals[1].errno = errno.ENOENT

                # Exact class and original traceback are necessary, not just
                # a matching name/message/filename or a stale prior capture.
                class Refused(ValueError): pass
                for error in (Refused('file-original-policy'), donor.Refused(private)):
                    quota = SimpleNamespace(call=mock.Mock(side_effect=error))
                    with mock.patch.object(C.os, 'stat', return_value=SimpleNamespace(st_uid=0)):
                        try: C._admit_system_tool(SimpleNamespace(outer=book, quota=quota), 'git', '/usr/bin/git')
                        except BaseException as raised: self.assertIs(raised, error)
                        else: self.fail('original failure was swallowed')
                    value = C.failure_data(error)
                    self.assertEqual(value['reason'], 'unavailable')
                    self.assertIsNone(value['systemTool'])
                    self.assertNotIn(private, R.canonical(value).decode())
                code = compile('def forged():\n    raise original\n', donor.__file__, 'exec')
                fake = FunctionType(next(c for c in code.co_consts if hasattr(c, 'co_code')),
                    {'original': donor.Refused('file-original-policy')})
                try: fake()
                except donor.Refused as error: forged = error
                C._SYSTEM_TOOL_FAILURE = (forged, 'git', donor.Originals)
                self.assertIsNone(C.failure_data(forged)['systemTool'])
                self.assertEqual(C.failure_data(forged)['sourceFrames'], [])
                for role, kind in (('foreign', donor.Originals), ('git', type('Originals', (), {}))):
                    C._SYSTEM_TOOL_FAILURE = (originals[0], role, kind)
                    self.assertIsNone(C.failure_data(originals[0])['systemTool'])
                C._SYSTEM_TOOL_FAILURE = (originals[0], 'git', donor.Originals)
                self.assertIsNone(C.failure_data(RuntimeError(private))['systemTool'])

                # Recording itself can fail: re-raise the identical primary,
                # and do not replace it with a diagnostic access exception.
                class CaptureFault:
                    accesses = 0
                    quota = SimpleNamespace(call=mock.Mock(side_effect=originals[0]))
                    @property
                    def outer(self):
                        self.accesses += 1
                        if self.accesses > 1: raise RuntimeError(private)
                        return book
                C._SYSTEM_TOOL_FAILURE = None
                with mock.patch.object(C.os, 'stat', return_value=SimpleNamespace(st_uid=0)):
                    with self.assertRaises(donor.Refused) as raised:
                        C._admit_system_tool(CaptureFault(), 'git', '/usr/bin/git')
                self.assertIs(raised.exception, originals[0])
                self.assertIsNone(C._SYSTEM_TOOL_FAILURE)
                C._SYSTEM_TOOL_FAILURE = (originals[0], 'git', donor.Originals)
                with mock.patch.dict(C.os.environ, {}, clear=True):
                    with self.assertRaises(R.Refused): C.main()
                self.assertIsNone(C._SYSTEM_TOOL_FAILURE)
        finally:
            C._SYSTEM_TOOL_FAILURE = previous
            sys.modules.pop('_mrk_p0_originals', None)
            if old_module is not None: sys.modules['_mrk_p0_originals'] = old_module

    def test_source_git_blob_join_rejects_changed_missing_duplicate_and_foreign_bytes(self):
        import hashlib
        files = {'desktop/tools/current.py': b'current source\n', 'desktop/macos-installed-inputs/build-release.json': b'{}\n'}
        def row(name, body):
            blob = hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest().encode()
            return b'100644 blob ' + blob + b'\t' + name.encode() + b'\0'
        rows = [row(name, body) for name, body in files.items()]
        C.source_rows_data(b''.join(rows), files)
        for body in (rows[0], rows[0] + rows[0], b''.join(rows)[:-1],
                     row('foreign', b'other') + rows[1], row(next(iter(files)), b'changed') + rows[1]):
            with self.assertRaises(ValueError): C.source_rows_data(body, files)

    def test_actual_original_quota_funds_full_two_root_plan_without_live_fd_credits(self):
        class Book:
            def __init__(self): self.entries, self.directories = [], {}
            def directory(self, path):
                if path not in self.directories:
                    if path != Path('/'): self.directory(path.parent)
                    value = {'path': path, 'kind': 'directory'}
                    self.entries.append(value); self.directories[path] = value
                return self.directories[path]
            def file(self, path, *args, **kwargs):
                self.directory(path.parent)
                value = {'path': path, 'kind': 'file'}
                self.entries.append(value)
                return value, b'inert'
        quota = R.OriginalQuota(); quota.reserve(2)  # mkdir + consumed bootstrap
        outer = quota.book(Book)
        work = Path('/Users/runner/work/_temp/mrk-macos-installed.ABCDEFGH/resume-carrier')
        quota.call(outer, 'directory', work)
        helper_files = (*C.HELPER_SOURCE_INPUTS, C.SELECTION_PATH, C.CONSUMER_PATH, C.LEGACY_PATH, C.PARSER_PATH,
                        R.SIGNING_CERTIFICATE[0], R.TLS_CA_PATH)
        for path in helper_files: quota.call(outer, 'file', C.HELPER_ROOT / path, 1)
        for path in (C.STAGER_PATH, *(path for path, _cap in C.CANDIDATE_SOURCE_INPUTS)):
            quota.call(outer, 'file', C.CANDIDATE_ROOT / path, 1)
        host = work.parent / 'host-python'
        quota.call(outer, 'file', host / 'host-binding.json', 1)
        for path in R.HOST_DIRS: quota.call(outer, 'directory', host / path)
        for path in (*R.HOST_FILES, R.HOST_OPTIONAL): quota.call(outer, 'file', host / path, 1)
        for path in ('/usr/bin/git', '/usr/bin/hdiutil', '/usr/bin/vm_stat', '/usr/bin/openssl', '/usr/bin/codesign', '/usr/sbin/installer'):
            quota.call(outer, 'file', Path(path), 1)
        quota.reserve(4)  # actual FixedSudoOriginals remains independent
        self.assertEqual(quota.reserved, 76)
        quota.reserve(3)  # acquisition child CA/root/output originals
        quota.call(outer, 'file', work / 'arm64-candidate.zip', 1)
        quota.reserve(1)  # actual image publisher original
        quota.call(outer, 'file', work / 'arm64.dmg', 1)
        quota.call(outer, 'directory', Path('/Volumes'))
        mounted = quota.book(Book)
        mounted.directories.update({path: entry for path, entry in outer.directories.items()
                                    if path in (Path('/'), Path('/Volumes'))})
        mount = Path('/Volumes/inert')
        quota.call(mounted, 'directory', mount)
        for path in ('Install.pkg', 'producer.json', 'producer.sig'): quota.call(mounted, 'file', mount / path, 1)
        for path in ('producer-key.pem', 'producer-message.bin', 'producer-message.bin'):
            quota.call(outer, 'file', work / path, 1)
        quota.call(outer, 'directory', work / 'input')
        quota.call(outer, 'file', work / 'input/install-inventory.json', 1)
        quota.call(outer, 'file', work / 'installer-output.status', 1)
        for _ in range(3): quota.reserve(1)  # original transport iterators
        self.assertEqual(quota.reserved, R.MAX_ORIGINALS)
        with self.assertRaises(ValueError): quota.reserve(1)
