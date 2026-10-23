"""Candidate owner adapter DATA/call-seam tests; never native or network tests.

Authored detached. Run only after the parent explicitly authorizes a focused
networkless test invocation; no workflow/carrier/native qualification follows.
"""
from collections import namedtuple
from contextlib import ExitStack, contextmanager
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


def retained_instance(selection):
    with mock.patch.object(R.Resume, '__init__', return_value=None):
        owner = C.CandidateResume(C.HELPER_ROOT, C.CANDIDATE_ROOT, Path('/inert'), None, None,
                                  retained_observer=True)
    owner.source = mock.Mock(return_value=R.canonical(selection))
    owner.load_nomination('aarch64-apple-darwin')
    return owner


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
    def test_retained_observer_is_explicit_arm_install_and_held_helper_selection_only(self):
        from tests.desktop.test_macos_candidate_carrier import retained_fixture
        selection, *_ = retained_fixture()
        owner = retained_instance(selection)
        owner.source.assert_called_once_with(C.RETAINED_OBSERVER_SELECTION_PATH, 8192)
        self.assertEqual(owner.nomination, selection['origin'])
        self.assertEqual(owner.retained_selection(), selection)
        exposed = owner.retained_selection(); exposed['members'][0]['bytes'] = 1
        exposed['origin']['source'] = 'e'*40
        self.assertEqual(owner.retained_selection(), selection)
        with self.assertRaisesRegex(R.Refused, 'candidate-source-selection-once'):
            owner.load_nomination('aarch64-apple-darwin')
        self.assertEqual(owner.source.call_count, 1)
        with self.assertRaisesRegex(R.Refused, 'retained-observer-source-not-loaded'):
            instance().retained_selection()
        for options in ({'purpose':'acquire'}, {'purpose':'restore-install'}, {'predecessor_install':True},
                        {'nomination':selection['origin']}, {'retained_observer':1}):
            with mock.patch.object(R.Resume, '__init__') as native, self.assertRaises(ValueError):
                C.CandidateResume(C.HELPER_ROOT, C.CANDIDATE_ROOT, Path('/inert'), None, None,
                                  **dict({'retained_observer':True}, **options))
            native.assert_not_called()
        env = PredecessorInstallTests().environment()
        env.update(MRK_CANDIDATE_MODE='install-retained-observer',
            GITHUB_REF='refs/heads/'+C.RETAINED_OBSERVER_BRANCH,
            GITHUB_WORKFLOW_REF=R.REPOSITORY+'/'+C.WORKFLOW+'@refs/heads/'+C.RETAINED_OBSERVER_BRANCH)
        self.assertEqual(C.context_data(env, C.HELPER_ROOT, 'arm64')['helperSource'], env['GITHUB_SHA'])
        for changes in ({'GITHUB_EVENT_NAME':'push'}, {'MRK_CANDIDATE_MODE':'install-predecessor'},
                {'GITHUB_REF':'refs/heads/'+C.BRANCH}, {'GITHUB_SHA':selection['origin']['source']},
                {'MRK_MACOS_TARGET':'x86_64-apple-darwin','RUNNER_ARCH':'X64'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                C.context_data(dict(env, **changes), C.HELPER_ROOT,
                    'x86_64' if changes.get('RUNNER_ARCH') == 'X64' else 'arm64')

    def test_retained_acquisition_original_request_and_zip_keep_only_plain_image(self):
        from tests.desktop.test_macos_candidate_carrier import retained_fixture
        selection, entries, body, *_ = retained_fixture()
        for fault in (None, 'child', 'post', 'capacity'):
            owner = retained_instance(selection)
            owner._CandidateResume__source_loaded = True
            owner.work, owner.private, owner._resource_inputs = Path('/inert'), {}, (0,0)
            owner.parent = {'identity':(1,2,stat.S_IFDIR|0o700,501,20)}
            owner.ca_path, owner.ca_sha, owner.token = '/inert/ca.pem', 'a'*64, 'inert-not-a-token'
            owner.python, owner.child_bootstrap, owner.environment = '/inert/python', 'inert-child-source', {}
            owner.clock, owner.point = R.Deadline(now=lambda:1), mock.Mock()
            original = {'identity':(1,2,3)}
            owner.quota = SimpleNamespace(reserve=mock.Mock(), call=mock.Mock(return_value=(original,body)))
            events = []
            def acquired(role, argv, seconds, *, env):
                events.append('child')
                self.assertEqual((role, argv, seconds), ('acquire-carrier',
                    ['/inert/python','-I','-S','-B','-c','inert-child-source'],120))
                request = R.decode(env['MRK_P0_REQUEST'].encode())
                self.assertEqual(request['row'], selection)
                self.assertEqual(request['role'], 'retained-observer')
                self.assertEqual(request['workIdentity'], list(owner.parent['identity']))
                self.assertEqual(set(env), {'MRK_P0_REQUEST','MRK_P0_READ_TOKEN'})
                return SimpleNamespace(returncode=1 if fault == 'child' else 0, stderr=b'', stdout=R.canonical({
                    'schemaVersion':1, 'role':'retained-observer', 'target':owner.target,
                    'bytes':len(body), 'sha256':R.sha(body), 'closedMetadataMatched':True, 'originalClosesKnown':True}))
            owner.command = mock.Mock(side_effect=acquired)
            def admit(*args, **kwargs):
                events.append('capacity')
                self.assertEqual(args, (0,0))
                self.assertEqual(kwargs, {'image_bytes':len(dict(entries)[C.candidate.RETAINED_OBSERVER_IMAGE]), 'acquiring':True})
                if fault == 'capacity': raise R.Refused('inert retained capacity')
            owner.admit_resources = mock.Mock(side_effect=admit)
            def post(book, entry, content, clock):
                events.append('post'); self.assertIs(entry, original)
                self.assertIs(book, owner.outer); self.assertIs(content, body); self.assertIs(clock, owner.clock)
                if fault == 'post': raise R.Refused('inert retained original post')
            owner.outer = SimpleNamespace(read=mock.Mock())
            with self.subTest(fault=fault), mock.patch.object(C.candidate, 'candidate_preview_data') as preview, \
                    mock.patch.object(R, 'retained_image_post', side_effect=post):
                if fault is None:
                    self.assertEqual(owner.acquire_candidate(), {C.candidate.RETAINED_OBSERVER_IMAGE:dict(entries)[C.candidate.RETAINED_OBSERVER_IMAGE]})
                    self.assertEqual(R.decode(owner._CandidateResume__members_document),
                        [dict(name=name,bytes=len(value),sha256=R.sha(value)) for name,value in entries])
                    self.assertFalse(hasattr(owner, '_CandidateResume__preview_document'))
                    self.assertTrue(owner._CandidateResume__artifact_admitted)
                else:
                    with self.assertRaises(R.Refused): owner.acquire_candidate()
                    self.assertFalse(owner._CandidateResume__artifact_admitted)
                preview.assert_not_called()
                owner.outer.read.assert_not_called()
            self.assertEqual(events, ['child'] + ([] if fault == 'child' else ['capacity'])
                             + ([] if fault in ('child','capacity') else ['post']))
            owner.quota.reserve.assert_called_once_with(3)
            if fault != 'child':
                owner.quota.call.assert_called_once_with(owner.outer,'file',owner.work/'arm64-retained-observer.zip',len(body),modes=(0o600,))
            with self.assertRaisesRegex(R.Refused, 'candidate-acquire-order'): owner.acquire_candidate()
            self.assertEqual(owner.command.call_count,1)

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
            self.assertEqual(after['acquisitionMemory'] - before['acquisitionMemory'], 6 * 17)
            self.assertEqual(before['acquisitionMemory'], 6 * row['artifactBytes'] + (16 << 20) + 4096 + (512 << 20) + (1 << 30))
            self.assertEqual(before['requiredDisk'], (3 << 30) + 2 * row['artifactBytes'] + 2 * R.LIMIT + 2048)
            self.assertEqual(after['acquisitionMemory'] - after['postAcquisitionMemory'], 6 * row['artifactBytes'])
            self.assertEqual(after['requiredDisk'], (3 << 30) + 2 * row['artifactBytes'] + 34 + 2048)
            larger = C.candidate_resource_requirements(dict(row, artifactBytes=R.LIMIT), 4096, 2048, image_bytes=17)
            self.assertEqual(larger['acquisitionMemory'] - after['acquisitionMemory'], 6 * (R.LIMIT - row['artifactBytes']))
        for retained, host, image in ((True, 0, None), (0, -1, None), (0, 0, True), (0, 0, R.LIMIT + 1)):
            with self.assertRaises(ValueError): C.candidate_resource_requirements(nomination(), retained, host, image_bytes=image)

    def test_removal_nomination_is_separate_once_only_and_matches_checkout_routing(self):
        import json
        bodies = {path: (ROOT / path).read_bytes() for path in (C.SELECTION_PATH, C.REMOVAL_SELECTION_PATH)}
        old, removal = (json.loads(bodies[path])['targets'] for path in (C.SELECTION_PATH, C.REMOVAL_SELECTION_PATH))
        self.assertEqual(removal['x86_64-apple-darwin'], old['x86_64-apple-darwin'])
        self.assertNotEqual(removal['aarch64-apple-darwin']['source'], old['aarch64-apple-darwin']['source'])
        workflow = (ROOT / C.WORKFLOW).read_text()
        ordinary, manual = workflow.split('\n  remove-delivery:\n', 1)
        self.assertIn("MRK_CANDIDATE_SOURCE: '" + old['aarch64-apple-darwin']['source'] + "'", ordinary)
        line, = (line.strip() for line in manual.splitlines() if line.strip().startswith('MRK_CANDIDATE_SOURCE:'))
        prefix, suffix = "MRK_CANDIDATE_SOURCE: ${{ fromJSON('", "')[matrix.target] }}"
        self.assertTrue(line.startswith(prefix) and line.endswith(suffix))
        routing = json.loads(line[len(prefix):-len(suffix)])
        self.assertEqual(routing, {target: row['source'] for target, row in removal.items()})
        self.assertEqual(json.loads((ROOT / 'desktop/macos-installed-inputs/update-predecessors.json').read_bytes()),
                         {'schemaVersion': 1, 'mode': 'unconfigured'})
        for purpose in C.PURPOSES:
            selected = C.REMOVAL_SELECTION_PATH if purpose == 'acquire-removal' else C.SELECTION_PATH
            for target in old:
                with self.subTest(purpose=purpose, target=target), mock.patch.object(R.Resume, '__init__', return_value=None):
                    owner = C.CandidateResume(C.HELPER_ROOT, C.CANDIDATE_ROOT, Path('/inert'), None, None, purpose=purpose)
                    owner.source = mock.Mock(side_effect=lambda path, _limit: bodies[path])
                    owner.load_nomination(target)
                    owner.source.assert_called_once_with(selected, 8192)
                    self.assertEqual(owner.nomination, C.selection_data(bodies[selected], target))
                    exposed = owner.nomination; exposed['jobId'] = '1'
                    self.assertNotEqual(owner.nomination['jobId'], '1')
                    with self.assertRaisesRegex(R.Refused, 'candidate-source-selection-once'): owner.load_nomination(target)
                    self.assertEqual(owner.source.call_count, 1)
            for failure in (FileNotFoundError('inert missing source'), R.Refused('inert original source refusal')):
                with mock.patch.object(R.Resume, '__init__', return_value=None):
                    owner = C.CandidateResume(C.HELPER_ROOT, C.CANDIDATE_ROOT, Path('/inert'), None, None, purpose=purpose)
                owner.source = mock.Mock(side_effect=failure)
                with self.assertRaises(type(failure)) as caught: owner.load_nomination('aarch64-apple-darwin')
                self.assertIs(caught.exception, failure)
                owner.source.assert_called_once_with(selected, 8192)  # No old-donor fallback.
                with self.assertRaisesRegex(R.Refused, 'candidate-source-selection-not-loaded'): _ = owner.nomination

    def test_all_removal_phases_hold_and_decode_only_the_removal_nomination(self):
        import resource
        from desktop.tools import macos_android_helper_package as H
        body = (ROOT / C.REMOVAL_SELECTION_PATH).read_bytes()
        decode = C.selection_data
        identity = tuple(range(9))  # Inert SOURCE port, not a native receipt.
        bootstrap = (C.resume_identity({'identity': identity}),
                     C.HELPER_ROOT / 'desktop/tools/macos_android_helper_package.py', b'inert held source')
        for target, machine, arch in (('aarch64-apple-darwin', 'arm64', 'ARM64'), ('x86_64-apple-darwin', 'x86_64', 'X64')):
            for phase in C.REMOVAL_PHASES:
                env = dict(MRK_MACOS_TARGET=target, GITHUB_WORKSPACE=str(C.CANDIDATE_ROOT), RUNNER_TEMP='/Users/runner/work/_temp',
                    GITHUB_REPOSITORY=R.REPOSITORY, GITHUB_EVENT_NAME='workflow_dispatch', MRK_CANDIDATE_MODE='remove-delivery',
                    GITHUB_REF='refs/heads/' + C.REMOVAL_BRANCH,
                    GITHUB_WORKFLOW_REF=R.REPOSITORY + '/' + C.WORKFLOW + '@refs/heads/' + C.REMOVAL_BRANCH,
                    GITHUB_SHA='d'*40, GITHUB_WORKFLOW_SHA='d'*40, RUNNER_OS='macOS', RUNNER_ARCH=arch,
                    RUNNER_ENVIRONMENT='github-hosted', GITHUB_RUN_ID='51', GITHUB_RUN_ATTEMPT='2',
                    MRK_MACOS_WORK='/Users/runner/work/_temp/mrk-macos-installed.ABCDEFGH')
                allowed = (H.INSTALLER_CREDENTIAL_VARIABLES + (H.NOTARY_KEY_VARIABLE,) if phase == 'finalize-remove-package' else
                           H.CREDENTIAL_VARIABLES if phase == 'package-remove' else
                           (H.NOTARY_KEY_VARIABLE,) if phase == 'finalize-remove-image' else ())
                env.update({key: 'inert-not-a-credential' for key in allowed})
                context = C.context_data(env, C.HELPER_ROOT, machine)
                op = H.Operation(None, C.CANDIDATE_ROOT, context['work'].parent,
                    'package-remove' if phase == 'remove-preview' else phase, env, None, target=target)
                op.source_original = mock.Mock(side_effect=lambda path, *_args: {'path': path, 'identity': identity})
                op.read = mock.Mock(side_effect=lambda entry: body if entry['path'] ==
                    '.candidate-consumer-helper/' + C.REMOVAL_SELECTION_PATH else bootstrap[2])
                op.open, op.finish = mock.Mock(), mock.Mock()
                op.execute = mock.Mock(side_effect=lambda: op.candidate_removal_load())
                stop = RuntimeError('inert stop before native owner/module entry')
                def selected(value, selected_target):
                    self.assertEqual(value, body)
                    self.assertEqual(decode(value, selected_target), decode(body, target))
                    raise stop
                with self.subTest(target=target, phase=phase), mock.patch.dict(C.os.environ, env, clear=True), \
                        mock.patch.object(C, 'ROOT', C.HELPER_ROOT), mock.patch.object(C.platform, 'machine', return_value=machine), \
                        mock.patch.object(resource, 'getrlimit', return_value=(256, 256)), \
                        mock.patch.object(H, 'Operation', return_value=op), mock.patch.object(H, 'emit_failure_diagnostic'), \
                        mock.patch.object(C, 'selection_data', side_effect=selected) as selection, mock.patch.object(R, 'load_module') as native:
                    with self.assertRaises(RuntimeError) as caught: H.candidate_removal_phase(C, context, phase, bootstrap)
                    self.assertIs(caught.exception, stop)
                    selection.assert_called_once_with(body, target)
                    paths = [call.args[0] for call in op.source_original.call_args_list]
                    self.assertEqual(paths.count('.candidate-consumer-helper/' + C.REMOVAL_SELECTION_PATH), 1)
                    self.assertNotIn('.candidate-consumer-helper/' + C.SELECTION_PATH, paths)
                    native.assert_not_called()
                    self.assertEqual(op.calls, [])
                    self.assertEqual(op.finish.call_count, int(phase == 'remove-preview'))

    def test_staged_image_read_retains_zip_allowance_until_original_post(self):
        import json
        from tests.desktop.test_macos_candidate_carrier import fixture, archive
        row, preview, *_ = fixture()
        body, selected = archive(row, [('MobileReleaseKit.dmg', b'DATA'),
            ('PREVIEW.json', json.dumps(preview).encode()), ('README.md', b'Guide\n')])
        initial = C.candidate_resource_requirements(selected, 0, 0)['acquisitionMemory']
        full = C.candidate_resource_requirements(selected, 0, 0, image_bytes=4)
        for mode in ('pass', 'capacity', 'post'):
            with mock.patch.object(R.Resume, '__init__', return_value=None):
                owner = C.CandidateResume(C.HELPER_ROOT, C.CANDIDATE_ROOT, Path('/inert'), None, None, nomination=selected)
            owner.work, owner.private, owner._resource_inputs = Path('/inert'), {}, (0, 0)
            owner.sources, owner.child_bootstrap = [], ''
            owner.clock, owner.host, owner.parent = SimpleNamespace(check=lambda: None), object(), {'fd': 7}
            owner.command = mock.Mock(return_value=SimpleNamespace(stdout=b'', stderr=b'', returncode=0))
            entry = {'identity': (1, 2, 3)}  # Explicit inert filesystem ports.
            owner.quota = SimpleNamespace(call=mock.Mock(return_value=(entry, body)))
            events = []
            def post(_):
                events.append('post')
                self.assertEqual(owner.memory_base, full['acquisitionMemory'])
                return b'changed' if mode == 'post' else body
            owner.outer = SimpleNamespace(read=post)
            actual = C.candidate.zip_data
            def decode(*args):
                events.append('decode')
                self.assertEqual(owner.memory_base, full['acquisitionMemory'])
                return actual(*args)
            with self.subTest(mode=mode), mock.patch.dict(R.STATE), \
                    mock.patch.object(R, 'host_memory_data', return_value=(4096, 1 << 40)), \
                    mock.patch.object(R, 'memory_data', return_value={'availableEstimateBytes': initial + 1 if mode == 'capacity' else 1 << 40}), \
                    mock.patch.object(C.os, 'fstatvfs', return_value=SimpleNamespace(f_bavail=1 << 40, f_frsize=1)), \
                    mock.patch.object(C.candidate, 'zip_data', side_effect=decode):
                owner.admit_resources(0, 0)
                self.assertEqual(owner.memory_base, initial)
                if mode == 'pass':
                    self.assertEqual(owner.read_candidate_zip()['MobileReleaseKit.dmg'], b'DATA')
                    self.assertEqual(events, ['decode', 'post'])
                    owner.admit_resources(0, 0, image_bytes=4)
                    self.assertEqual(owner.memory_base, full['postAcquisitionMemory'])
                    self.assertEqual(full['acquisitionMemory'] - owner.memory_base, 6 * selected['artifactBytes'])
                else:
                    with self.assertRaisesRegex(R.Refused, 'candidate-resource-admission' if mode == 'capacity' else 'candidate-acquisition-original-post'):
                        owner.read_candidate_zip()
                    self.assertEqual(events, [] if mode == 'capacity' else ['decode', 'post'])
                    self.assertFalse(owner._CandidateResume__artifact_admitted)
                self.assertEqual(owner.command.call_count, 3 if mode == 'pass' else 2)

    def test_package_memory_credit_follows_complete_reads_and_precedes_codecs(self):
        image = b'image'
        for fault in ('pass', 'read', 'before', 'after'):
            originals, row, stage = mounted_fixture('aarch64-apple-darwin')
            with mock.patch.object(R.Resume, '__init__', return_value=None):
                owner = C.CandidateResume(C.HELPER_ROOT, C.CANDIDATE_ROOT, Path('/inert'), None, None,
                                         nomination=nomination())
            owner._CandidateResume__artifact_admitted = True
            owner._CandidateResume__members_document = R.canonical(row['members'])
            owner.selection = stage.source_build_selection(owner.target)
            stage.PRODUCER_DESCRIPTOR_BYTES = stage.PRODUCER_SIGNATURE_BYTES = 65536
            owner.stager, owner.signing_identity = stage, row['signingIdentity']
            owner._resource_inputs, owner.sources, owner.child_bootstrap = (0, 0), [], ''
            owner.clock, owner.host, owner.parent = SimpleNamespace(check=lambda: None), object(), {'fd': 7}
            owner.point = lambda: None
            owner.command = mock.Mock(return_value=SimpleNamespace(stdout=b'', stderr=b'', returncode=0))
            quote = C.candidate_resource_requirements(nomination(), 0, 0, image_bytes=len(image))
            package = len(originals['Install.pkg'][0])
            fixed = quote['postAcquisitionMemory'] - 5 * len(image) + 2 * 65536
            before, after = fixed + 6 * package, fixed + package
            owner.memory_base = quote['postAcquisitionMemory']
            calls = []
            def read(book, operation, path, *args, **kwargs):
                self.assertEqual(owner.memory_base, before)
                calls.append(path.name)
                if fault == 'read' and path.name == 'producer.sig': raise OSError('inert-read')
                return {}, originals[path.name][0]
            owner.quota = SimpleNamespace(call=read)
            preview = {key + 'Sha256': row[key]['sha256'] for key in ('package', 'descriptor', 'signature')}
            preview.update(packageSize=package, installerInventorySha256=row['inventorySha256'],
                           runtimeManifestSha256=row['runtimeManifestSha256'])
            def parse(*args, **kwargs):
                self.assertEqual(owner.memory_base, after)
                self.assertEqual(calls, list(originals))
                return {}, b'inventory'
            with self.subTest(fault=fault), mock.patch.dict(R.STATE), \
                    mock.patch.object(R, 'host_memory_data', return_value=(4096, 1 << 40)), \
                    mock.patch.object(R, 'memory_data', side_effect=[
                        {'availableEstimateBytes': 0 if fault == 'before' else 1 << 40},
                        {'availableEstimateBytes': 0 if fault == 'after' else 1 << 40}]), \
                    mock.patch.object(C.os, 'fstatvfs', return_value=SimpleNamespace(f_bavail=1 << 40, f_frsize=1)), \
                    mock.patch.object(C.os, 'stat', side_effect=lambda name, **kw: SimpleNamespace(
                        st_mode=stat.S_IFREG | 0o444, st_size=len(originals[name][0]),
                        st_uid=C.os.getuid(), st_gid=C.os.getgid())), \
                    mock.patch.object(R, 'mounted_data', side_effect=parse) as parser:
                if fault == 'pass':
                    owner.read_mounted(object(), {'fd': 8}, Path('/inert'), image, preview)
                    parser.assert_called_once()
                    self.assertEqual(owner.memory_base, after)
                    self.assertEqual(owner.allocation_samples, 0)
                else:
                    with self.assertRaises((OSError, R.Refused)):
                        owner.read_mounted(object(), {'fd': 8}, Path('/inert'), image, preview)
                    parser.assert_not_called()
                    self.assertIsNone(owner._CandidateResume__binding)
                    self.assertEqual(owner.memory_base, quote['postAcquisitionMemory'] if fault == 'before' else before)
                    if fault == 'before': self.assertEqual(calls, [])
            self.assertEqual(owner.command.call_count, 1 if fault in ('read', 'before') else 2)
        # Invalid stage combinations fail before sampling native capacity.
        for options in ({'reading': True}, {'reading': 1}, {'package_bytes': True},
                        {'package_bytes': 1, 'acquiring': True}, {'package_bytes': R.LIMIT + 1}):
            owner.command.reset_mock()
            with self.assertRaises(R.Refused):
                owner.admit_resources(0, 0, image_bytes=1, **options)
            owner.command.assert_not_called()

    def test_child_source_limits_precede_construction_and_sources_are_explicit(self):
        bodies = {name: (ROOT / name).read_bytes() for name in (C.LEGACY_PATH, C.PARSER_PATH)}
        self.assertLessEqual(len(bodies[C.LEGACY_PATH]), R.SOURCE_LIMIT)
        source = C.acquisition_bootstrap(C.HELPER_ROOT, bodies)
        self.assertLessEqual(len(source.encode()), C.CHILD_SOURCE_LIMIT)
        # Compile is syntax-only; do not exec the child or make an API request.
        compile(source, '<inert-candidate-bootstrap>', 'exec')
        for changed in ({C.LEGACY_PATH: b'x' * ((R.SOURCE_LIMIT) + 1), C.PARSER_PATH: b'x'},
                        {C.LEGACY_PATH: b'\x00' * (R.SOURCE_LIMIT), C.PARSER_PATH: b'x'},
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

    def test_restore_captures_one_real_cpio_decode_and_never_replaces_inventory(self):
        import gzip
        from desktop.tools import stage_macos_installed as codec
        from desktop.tools import macos_app_absence_fixture as fixture
        def odc(name, mode, body=b''):
            name = name.encode('ascii') + b'\0'
            fields = ((0,6),(1,6),(mode,6),(0,6),(0,6),(1,6),(0,6),(0,11),(len(name),6),(len(body),11))
            return b'070707' + ''.join(format(v, '0%do' % width) for v,width in fields).encode() + name + body
        for target in fixture.TARGETS:
            for bad in (False, True):
                with self.subTest(target=target, changed_inventory=bad):
                    originals, row, stage = mounted_fixture(target)
                    body = b'app bytes'; inventory = b'inventory'
                    archive = odc('.', stat.S_IFDIR | 0o755)
                    for name in ('input', 'input/app', 'input/runtime'):
                        archive += odc(name, stat.S_IFDIR | 0o555)
                    archive += odc('input/install-inventory.json', stat.S_IFREG | 0o444, inventory)
                    archive += odc('input/app/program', stat.S_IFREG | 0o555, body)
                    archive += odc('input/runtime/not-retained', stat.S_IFREG | 0o444, b'runtime bytes')
                    archive += odc('TRAILER!!!', 0)
                    stage.install_product_members.return_value = {'component/PackageInfo': b'info',
                        'component/Scripts': gzip.compress(archive)}
                    stage.inflate = codec.inflate
                    stage.cpio_members = mock.Mock(wraps=codec.cpio_members)
                    stage.observation_inventory_bytes.return_value = {
                        'app/program': {'size': len(body), 'sha256': R.sha(body), 'executable': True},
                        'runtime/not-retained': {'size': 13}}
                    with mock.patch.object(R.Resume, '__init__', return_value=None):
                        owner = C.CandidateResume(C.HELPER_ROOT, C.CANDIDATE_ROOT, Path('/inert'),
                                                 None, None, nomination=nomination(target), purpose='acquire-restore')
                    owner.fixture_api = fixture
                    owner._restore_originals = originals
                    owner.package_api = SimpleNamespace(candidate_materialize=mock.Mock())
                    phases = []
                    def budget(phase, *args):
                        if phase == 'cpio-window': self.assertNotIn(phase, phases)
                        phases.append(phase)
                    result, retained = R.mounted_data(originals, row, target, stage, candidate=True,
                        allocation_budget=budget, capture_scripts=owner._CandidateResume__capture_restore_scripts)
                    captured = owner._CandidateResume__restore_inputs
                    self.assertIs(captured[0], retained)
                    self.assertEqual(dict(captured[1]), {'input/app/program': (body, 0o555)})
                    with self.assertRaises(TypeError): captured[1]['other'] = (b'changed', 0o444)
                    with self.assertRaisesRegex(R.Refused, 'candidate-restore-capture-order'):
                        owner._CandidateResume__capture_restore_scripts(retained, {}, {})
                    owner.package_api.candidate_materialize.assert_not_called()
                    if bad:
                        with self.assertRaisesRegex(R.Refused, 'candidate-restore-captured-inventory'):
                            owner.prepare_readback(result, retained + b'changed')
                        owner.package_api.candidate_materialize.assert_not_called()
                    else:
                        # Native signature verification remains the caller's boundary.
                        self.assertIs(owner.prepare_readback(result, retained), False)
                        owner.package_api.candidate_materialize.assert_called_once_with(owner, originals, retained, captured[1])
                        self.assertIsNone(owner._CandidateResume__restore_inputs)
                    self.assertEqual(phases.count('cpio-window'), 1)
                    stage.cpio_members.assert_called_once()
        originals, row, stage = mounted_fixture(fixture.TARGETS[0])
        capture = mock.Mock()
        with self.assertRaisesRegex(R.Refused, 'resume-mounted-capture-purpose'):
            R.mounted_data(originals, row, row['target'], stage, capture_scripts=capture)
        capture.assert_not_called(); stage.cpio_members.assert_not_called()

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
            # Transport ports stay inert; complete real-FD image comparison has
            # its own bounded corruption/deadline/POST regression below.
            patches.enter_context(mock.patch.object(R, 'retained_image_post', side_effect=lambda book, entry, expected, clock:
                R.need(book.read(entry) == expected, 'resume-image-retained-post')))
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
            # Transport ports stay inert; complete real-FD image comparison has
            # its own bounded corruption/deadline/POST regression below.
            patches.enter_context(mock.patch.object(R, 'retained_image_post', side_effect=lambda book, entry, expected, clock:
                R.need(book.read(entry) == expected, 'resume-image-retained-post')))
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
        from desktop.tools import macos_android_helper_package as helper
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
            manual = dict(env, GITHUB_EVENT_NAME='workflow_dispatch', MRK_CANDIDATE_MODE='remove-delivery',
                GITHUB_REF='refs/heads/'+C.REMOVAL_BRANCH,
                GITHUB_WORKFLOW_REF=R.REPOSITORY+'/'+C.WORKFLOW+'@refs/heads/'+C.REMOVAL_BRANCH)
            self.assertEqual(C.context_data(manual,C.HELPER_ROOT,machine)['target'],target)
            # Execute the actual final-image entry guard with validated H/P
            # context. The sentinel is BEFORE native/notary or filesystem work.
            admitted = C.context_data(manual, C.HELPER_ROOT, machine)
            admitted.update(productSource=nomination(target)['source'])
            def operation(phase='finalize-remove-image', environment=None):
                op = helper.Operation(None, C.CANDIDATE_ROOT, admitted['work'].parent,
                    phase, dict(manual if environment is None else environment), None, target=target)
                op.signing = ('INERTTEAM0', 'a' * 40)
                op.candidate_removal_context = dict(admitted)
                op.candidate_removal_root = object()  # Only the already-loaded-root latch.
                return op
            stop = RuntimeError('inert-notary-entry')
            for phase, ref, candidate in (
                    ('finalize-remove-image', manual['GITHUB_REF'], True),
                    ('finalize-remove-image', 'refs/heads/verify/desktop-macos-preview', False),
                    ('finalize-image', 'refs/heads/verify/desktop-macos-preview', False),
                    ('finalize-image', 'refs/heads/verify/desktop-macos-installed', False),
                    ('finalize-image', helper.CANDIDATE_REF, False)):
                op = operation(phase, dict(manual, GITHUB_REF=ref))
                if not candidate:
                    op.candidate_removal_context = op.candidate_removal_root = None
                with self.subTest(finalImage=phase, ref=ref), mock.patch.object(op, 'notary_space', side_effect=stop) as reserve:
                    with self.assertRaises(RuntimeError) as caught: op.finalize_image()
                    self.assertIs(caught.exception, stop)
                    reserve.assert_called_once_with(reserve=True)
                    self.assertEqual(op.calls, [])
            changes = (
                ('candidate_removal_context', None), ('candidate_removal_root', None),
                ('removal', False), ('signing', None), ('phase', 'finalize-image'),
                ('phase', 'package-remove'),
                ('GITHUB_EVENT_NAME', 'push'), ('GITHUB_REF', 'refs/heads/main'),
                ('GITHUB_REF', helper.CANDIDATE_REF),
                ('GITHUB_WORKFLOW_REF', manual['GITHUB_WORKFLOW_REF'] + '-other'),
                *((key, 'inert-secret') for key in helper.CREDENTIAL_VARIABLES + helper.INSTALLER_CREDENTIAL_VARIABLES))
            for key, value in changes:
                op = operation()
                if key in ('candidate_removal_context', 'candidate_removal_root', 'removal', 'signing', 'phase'):
                    setattr(op, key, value)
                else:
                    op.environment[key] = value
                with self.subTest(finalImageRefused=key), mock.patch.object(op, 'notary_space') as reserve:
                    with self.assertRaisesRegex(helper.Refused, '^final-image-configured-purpose$') as caught:
                        op.finalize_image()
                    reserve.assert_not_called()
                    self.assertEqual(op.calls, [])
                    self.assertEqual(helper.failure_exception(caught.exception)['reason'], 'final-image-configured-purpose')
            for key,value in (('GITHUB_EVENT_NAME','push'),('MRK_CANDIDATE_MODE','restore'),
                              ('GITHUB_REF','refs/heads/'+C.BRANCH),('GITHUB_WORKFLOW_SHA','e'*40)):
                with self.assertRaises(ValueError): C.context_data(dict(manual,**{key:value}),C.HELPER_ROOT,machine)
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

    def test_resource_failure_projection_requires_actual_origin_and_finite_observation(self):
        from types import FunctionType
        private = 'PRIVATE-RESOURCE-DO-NOT-EXPORT'
        errors = []
        # Actual admission functions; only native sampling/command ports are inert.
        # No measured host capacity, resource reservation or native action claimed.
        for allocation, memory, disk, reason in (
                (False, 0, 1 << 40, 'candidate-resource-admission'),
                (True, 0, 1 << 40, 'resume-resource-memory-admission'),
                (True, 1 << 40, 0, 'resume-resource-disk-admission')):
            owner = instance()
            owner.sources, owner.child_bootstrap = [], ''
            owner.clock, owner.host, owner.parent = SimpleNamespace(check=lambda: None), object(), {'fd': 7}
            owner.command = mock.Mock(return_value=SimpleNamespace(stdout=b'', stderr=b'', returncode=0))
            owner.memory_base, owner.required_disk = 1, 1
            owner.allocation_samples, owner.cpio_window = 0, None
            with mock.patch.dict(R.STATE, resourceAdmission=None), \
                    mock.patch.object(R, 'host_memory_data', return_value=(4096, 1 << 40)), \
                    mock.patch.object(R, 'memory_data', return_value={'availableEstimateBytes': memory}), \
                    mock.patch.object(C.os, 'fstatvfs', return_value=SimpleNamespace(f_bavail=disk, f_frsize=1)):
                try:
                    if allocation: owner.allocation_budget('xar-toc', 0, 0, 1)
                    else: owner.admit_resources(0, 0)
                except R.Refused as error:
                    errors.append(error)
                    value = C.failure_data(error)
                else:
                    self.fail('original resource admission must refuse')
                self.assertEqual(value['reason'], reason)
                self.assertEqual(value['resourceAdmission'], R.STATE['resourceAdmission'])
                self.assertFalse(value['cleanupAuthorized'] or value['rawOutputExported'])
                self.assertEqual(value['resourceAdmission']['availableMemoryEstimateBytes'], memory)
                self.assertEqual(value['resourceAdmission']['availableDiskBytes'], disk)
                self.assertLess(len(R.canonical(value)), 4096)
                facts = dict(R.STATE['resourceAdmission'])
                for invalid in (None, dict(facts, private=private), dict(facts, requiredMemoryBytes=True),
                                dict(facts, memorySufficient=not facts['memorySufficient']),
                                dict(facts, availableDiskBytes=1 << 53)):
                    R.STATE['resourceAdmission'] = invalid
                    reduced = C.failure_data(errors[-1])
                    self.assertIsNone(reduced['resourceAdmission'])
                    self.assertEqual(reduced['reason'], reason)
                    self.assertNotIn(private, R.canonical(reduced).decode())
                R.STATE['resourceAdmission'] = facts
                with mock.patch.object(R, 'resource_projection_data', side_effect=RuntimeError(private)):
                    reduced = C.failure_data(errors[-1])
                    self.assertIsNone(reduced['resourceAdmission'])
                    self.assertEqual(reduced['reason'], reason)
                self.assertEqual(errors[-1].args, (reason,))
                # Stale facts do not attach to an unentered/impostor failure.
                for error in (R.Refused(reason), RuntimeError(private)):
                    self.assertIsNone(C.failure_data(error)['resourceAdmission'])
                code = compile('def admit_resources():\n    raise Refused("' + reason + '")\n', C.__file__, 'exec')
                for namespace in ({'Refused': R.Refused}, dict(vars(C), Refused=R.Refused)):
                    function = FunctionType(next(q for q in code.co_consts if hasattr(q, 'co_code')), namespace)
                    try: function()
                    except R.Refused as error:
                        self.assertIsNone(C.failure_data(error)['resourceAdmission'])
            owner.command.assert_called_once_with('memory', ['/usr/bin/vm_stat'], 10)

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
        for selection, archive in ((C.SELECTION_PATH,'arm64-candidate.zip'),
                                   (C.RETAINED_OBSERVER_SELECTION_PATH,'arm64-retained-observer.zip')):
            with self.subTest(selection=selection):
                quota = R.OriginalQuota(); quota.reserve(2)  # mkdir + consumed bootstrap
                outer = quota.book(Book)
                work = Path('/Users/runner/work/_temp/mrk-macos-installed.ABCDEFGH/resume-carrier')
                quota.call(outer, 'directory', work)
                helper_files = (*C.HELPER_SOURCE_INPUTS, selection, C.CONSUMER_PATH, C.LEGACY_PATH, C.PARSER_PATH,
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
                quota.call(outer, 'file', work / archive, 1)
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
                quota.reserve(2)  # Original pre-attach and post-attach transport iterators.
                self.assertEqual(quota.reserved,95)  # Returned detach16 cannot enter the success-only third iterator.
                quota.reserve(1)
                self.assertEqual(quota.reserved, R.MAX_ORIGINALS)
                with self.assertRaises(ValueError): quota.reserve(1)
        # New read-only purpose never acquires Installer(1)/sudo(4), nor
        # install-input directory/inventory/status(3); it publishes five donors.
        removal = R.OriginalQuota()
        removal.reserve(76-5)
        removal.reserve(17+5)
        self.assertEqual(removal.reserved,93)
        removal.reserve(3)
        with self.assertRaises(ValueError): removal.reserve(1)

    def test_removal_donors_use_actual_exclusive_publisher_and_closed_acquisition(self):
        import os
        import tempfile
        from desktop.tools import macos_e2_native_fixture as E
        for fault in (None, 'collision', 'close'):
            with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
                work=Path(temp);work.chmod(0o700)
                clock=SimpleNamespace(check=lambda:None)
                owner=C.CandidateResume(C.HELPER_ROOT,C.CANDIDATE_ROOT,work,clock,E.Originals,
                    nomination=nomination(),purpose='acquire-removal')
                owner.selection=SimpleNamespace(package_version='0.1.2',release='macos26-arm64-candidate02')
                owner.installer_entered=False;owner.point=lambda:None
                owner.admit_resources=mock.Mock();owner._resource_inputs=(1,1)
                owner._CandidateResume__binding_image_bytes=10
                owner._restore_originals={name:(name.encode(),0o444) for name in C.REMOVAL_DONORS[:3]}
                owner._CandidateResume__removal_program=b'signed remover'
                owner.acquisition_result={}
                if fault=='collision': (work/'Install.pkg').write_bytes(b'original')
                original_close=owner.outer.close
                def close(entry):
                    original_close(entry)
                    if fault=='close' and entry['kind']=='output':
                        entry['closed']=False;owner.outer.errors.append('inert close unknown')
                try:
                    with mock.patch.object(owner.outer,'close',side_effect=close):
                        if fault is None: owner.publish_removal_inputs(b'inventory')
                        else:
                            with self.assertRaises((ValueError,FileExistsError)): owner.publish_removal_inputs(b'inventory')
                    if fault is None:
                        self.assertEqual(set(os.listdir(work)),set(C.REMOVAL_DONORS))
                        self.assertTrue(all(e['closed'] for e in owner.outer.entries if e['kind']=='output'))
                        self.assertEqual((work/'mrk-macos-remove').read_bytes(),b'signed remover')
                        self.assertEqual(stat.S_IMODE((work/'mrk-macos-remove').stat().st_mode),0o555)
                        owner.retire()
                        self.assertEqual(set(os.listdir(work)),set(C.REMOVAL_DONORS))
                        self.assertEqual(owner.acquisition_result['removalDonor']['sourcePackageVersion'],'0.1.2')
                    elif fault=='collision':
                        self.assertEqual((work/'Install.pkg').read_bytes(),b'original')
                        self.assertFalse((work/'producer.json').exists())
                    else:
                        self.assertFalse((work/'producer.json').exists())
                        self.assertFalse(owner.quota.finish())
                finally: owner.quota.finish()
        selected=SimpleNamespace(package_version='0.1.2',release='macos26-arm64-candidate02')
        fixed=dict(schemaVersion=1,scope='candidate-closed-acquisition',nomination=nomination(),
            helperSource='a'*40,helperTree='b'*40,consumerRunId='51',consumerRunAttempt='2',
            nativeProducerSignatureVerified=True,originalMountDetached=True,originalClosesKnown=True,
            installerEntered=False,productReady=False,runtimeManifestSha256='c'*64)
        for key,name in zip(('package','descriptor','signature','inventory','remover'),C.REMOVAL_DONORS):
            fixed[key]=dict(name=name,bytes=1,sha256='d'*64)
        fixed['removalDonor']=dict(sourcePackageVersion=selected.package_version,release=selected.release,removerSha256='d'*64)
        args=(nomination(),'a'*40,'b'*40,'51','2',selected)
        self.assertIs(C.removal_acquisition_data(fixed,*args),fixed)
        for key,val in (('originalClosesKnown',False),('originalMountDetached',False),('nativeProducerSignatureVerified',False),
                        ('helperSource','1'*40),('nomination',nomination('x86_64-apple-darwin')),('installerEntered',True)):
            with self.assertRaises(ValueError): C.removal_acquisition_data(dict(fixed,**{key:val}),*args)

    def test_removal_native_quote_preserves_unknown_originals_before_dispatch(self):
        from desktop.tools import macos_android_helper_package as H
        op=H.Operation(SimpleNamespace(run_owned=mock.Mock()),Path('/inert/source'),Path('/inert/work'),
            'package-remove',dict(GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40,GITHUB_WORKFLOW_REF='inert',
            GITHUB_RUN_ID='51',GITHUB_RUN_ATTEMPT='2',MRK_MACOS_PACKAGE_ROLE='ordinary-image'),None)
        op.candidate_removal_context={}
        op.entries=[dict(fd=None,closed=True) for _ in range(24576)]
        op.candidate_removal_quote()
        op.entries.append(dict(fd=None,closed=True))
        with self.assertRaises(H.Refused):op.candidate_removal_quote()
        op.entries=[dict(fd=3,closed=False) for _ in range(216)]
        op.candidate_removal_quote()
        op.entries.append(dict(fd=None,closed=False))  # Unknown close consumes a live slot.
        with self.assertRaises(H.Refused):
            op.call('producer-build',['inert'],{},cwd=op.work,timeout=1,limit=32)
        op.owner.run_owned.assert_not_called()

    def test_removal_manual_context_cannot_enter_installer_or_restore(self):
        with mock.patch.dict(C.os.environ, {'GITHUB_EVENT_NAME':'workflow_dispatch','MRK_CANDIDATE_MODE':'remove-delivery'}, clear=True):
            for purpose in ('install','acquire','acquire-restore','restore-install'):
                with self.subTest(purpose=purpose), mock.patch.object(C,'entry_context') as entry:
                    with self.assertRaises(ValueError): C.main(purpose)
                    entry.assert_not_called()
            with mock.patch.object(C,'entry_context',return_value={}), mock.patch.object(R,'host_read') as read:
                with self.assertRaises(ValueError): C.fixture_main('prepare-restore')
                read.assert_not_called()


class PredecessorInstallTests(unittest.TestCase):
    """Fixed public P0 routing and inert SAME-call diagnostics, never native proof."""

    def setUp(self):
        self.previous = C._PREDECESSOR_DETACH
        C._PREDECESSOR_DETACH = None

    def tearDown(self):
        C._PREDECESSOR_DETACH = self.previous

    def environment(self):
        return dict(MRK_MACOS_TARGET='aarch64-apple-darwin', GITHUB_WORKSPACE=str(C.CANDIDATE_ROOT),
            RUNNER_TEMP='/Users/runner/work/_temp', GITHUB_REPOSITORY=R.REPOSITORY,
            GITHUB_EVENT_NAME='workflow_dispatch', MRK_CANDIDATE_MODE='install-predecessor',
            GITHUB_REF='refs/heads/' + C.PREDECESSOR_BRANCH,
            GITHUB_WORKFLOW_REF=R.REPOSITORY + '/' + C.WORKFLOW + '@refs/heads/' + C.PREDECESSOR_BRANCH,
            GITHUB_SHA='d'*40, GITHUB_WORKFLOW_SHA='d'*40, RUNNER_OS='macOS', RUNNER_ARCH='ARM64',
            RUNNER_ENVIRONMENT='github-hosted', GITHUB_RUN_ID='51', GITHUB_RUN_ATTEMPT='2',
            MRK_MACOS_WORK='/Users/runner/work/_temp/mrk-macos-installed.ABCDEFGH')

    def owner(self, **options):
        with mock.patch.object(R.Resume, '__init__', return_value=None):
            value = C.CandidateResume(C.HELPER_ROOT, C.CANDIDATE_ROOT, Path('/inert'), None, None,
                                      predecessor_install=True, **options)
        value.clock = SimpleNamespace(finality=True)
        value.installer_zero = value.readback_known = True
        return value

    def test_final_reread_capture_aliases_only_the_three_acquired_originals(self):
        for predecessor in (False, True):
            originals, row, stage = mounted_fixture('aarch64-apple-darwin')
            owner = self.owner() if predecessor else instance()
            if predecessor: owner._CandidateResume__nomination = nomination()
            owner._CandidateResume__artifact_admitted = True
            owner._CandidateResume__members_document = R.canonical(row['members'])
            owner.selection = stage.source_build_selection(owner.target)
            stage.PRODUCER_DESCRIPTOR_BYTES = stage.PRODUCER_SIGNATURE_BYTES = 65536
            owner.stager, owner.signing_identity = stage, row['signingIdentity']
            owner.point = mock.Mock(); owner.admit_resources = mock.Mock(); owner._resource_inputs = (0,0)
            owner.allocation_budget = mock.Mock()
            mounted, entries = object(), {}
            def acquired(book, operation, path, *args, **kwargs):
                self.assertIs(book, mounted)
                self.assertEqual(operation, 'file')
                entry = entries[path.name] = {'path':path}
                return entry, originals[path.name][0]
            owner.quota = SimpleNamespace(call=acquired)
            preview = {key+'Sha256':row[key]['sha256'] for key in ('package','descriptor','signature')}
            preview.update(packageSize=len(originals['Install.pkg'][0]), installerInventorySha256=row['inventorySha256'],
                           runtimeManifestSha256=row['runtimeManifestSha256'])
            with self.subTest(predecessor=predecessor), mock.patch.object(C.os, 'stat', side_effect=lambda name, **kwargs:
                    SimpleNamespace(st_mode=stat.S_IFREG|0o444, st_size=len(originals[name][0]),
                                    st_uid=C.os.getuid(), st_gid=C.os.getgid())), mock.patch.object(C.os, 'open') as opened:
                returned, _, _, _ = owner.read_mounted(mounted, {'fd':-1}, Path('/inert'), b'image', preview)
                opened.assert_not_called()
            self.assertEqual(len(entries), 3)
            captured = owner._CandidateResume__mounted_reread_inputs
            if predecessor:
                self.assertIs(captured[0], mounted)
                self.assertEqual(tuple(name for name,entry,body in captured[1]), tuple(originals))
                for name,entry,body in captured[1]:
                    self.assertIs(entry, entries[name])
                    self.assertIs(body, originals[name][0])
                    self.assertIs(body, returned[name][0])
            else:
                self.assertIsNone(captured)

    def test_final_reread_reads_real_held_fds_in_bounded_blocks_without_reopening(self):
        import tempfile
        names = ('Install.pkg','producer.json','producer.sig')
        bodies = (b'P'*(2*65536+7), b'inert-descriptor', b'inert-signature')
        for corrupt in (False, True):
            with self.subTest(corrupt=corrupt), tempfile.TemporaryDirectory(prefix='.p0-reread-', dir=ROOT) as folder:
                entries, held, reads, identities = [], [], [], []
                try:
                    for name,body in zip(names,bodies):
                        path = Path(folder) / name
                        path.write_bytes(body); path.chmod(0o444)
                        fd = C.os.open(path, C.os.O_RDONLY | C.os.O_NOFOLLOW | C.os.O_CLOEXEC)
                        entry = {'fd':fd, 'closed':False, 'path':path, 'kind':'file', 'identity':R.identity(C.os.fstat(fd))}
                        entries.append(entry)
                        held.append((name,entry,body[:-1]+b'X' if corrupt and name == 'Install.pkg' else body))
                    def check_one(entry):
                        identities.append(entry)
                        R.need(R.identity(C.os.fstat(entry['fd'])) == entry['identity'] ==
                               R.identity(C.os.stat(entry['path'], follow_symlinks=False)), 'inert-original-identity')
                    book = SimpleNamespace(entries=entries, check_one=check_one)
                    owner = self.owner()
                    owner.mount_path = lambda: Path(folder)
                    owner.clock = R.Deadline(now=lambda:1)
                    owner.quota = SimpleNamespace(check=lambda: [check_one(entry) for entry in entries])
                    owner._CandidateResume__installed_signature_state = 'deferred'
                    owner._CandidateResume__mounted_reread_inputs = (book,tuple(held))
                    actual_pread = C.os.pread
                    def pread(fd, count, offset):
                        self.assertIs(owner.clock.finality, False)
                        self.assertIn(fd, [entry['fd'] for entry in entries])
                        self.assertLessEqual(count, 65536)
                        reads.append((fd,count,offset))
                        return actual_pread(fd,count,offset)
                    with mock.patch.dict(R.STATE), mock.patch.object(C.os, 'pread', side_effect=pread), \
                            mock.patch.object(C.os, 'open') as opened:
                        if corrupt:
                            with self.assertRaisesRegex(R.Refused, 'resume-image-retained-post'):
                                owner.pre_detach_originals(lambda:'same', 'same')
                            self.assertEqual(owner._CandidateResume__mounted_reread_state, 'entered')
                            self.assertEqual(reads, [(entries[0]['fd'],65536,0), (entries[0]['fd'],65536,65536),
                                                     (entries[0]['fd'],7,2*65536)])
                        else:
                            owner.pre_detach_originals(lambda:'same', 'same')
                            self.assertEqual(owner._CandidateResume__mounted_reread_state, 'verified')
                            expected = []
                            for entry,body in zip(entries,bodies):
                                expected += [(entry['fd'],min(65536,len(body)-offset),offset) for offset in range(0,len(body),65536)]
                                expected.append((entry['fd'],1,len(body)))
                            self.assertEqual(reads, expected)
                            self.assertTrue(all(sum(item is entry for item in identities) >= 2 for entry in entries))
                        self.assertIsNone(owner._CandidateResume__mounted_reread_inputs)
                        before = list(reads)
                        with self.assertRaisesRegex(R.Refused, 'candidate-predecessor-reread-order'):
                            owner.pre_detach_originals(lambda:'same', 'same')
                        self.assertEqual(reads, before)
                        opened.assert_not_called()
                finally:
                    for entry in entries: C.os.close(entry['fd'])

    @contextmanager
    def scheduled_install(self, mode='predecessor', fault=None):
        """Actual install/command/signature methods; inert native and FS ports."""
        import subprocess
        C._PREDECESSOR_DETACH = None
        retained = mode == 'retained-observer'
        events, native_calls, now = [], [], [1]
        original_error = RuntimeError('inert original unknown')
        image = b'inert-image'
        preview = {'distributionBytes': len(image), 'distributionSha256': R.sha(image)}
        if mode == 'fixed':
            owner = object.__new__(R.Resume)
            row = dict(R.ORIGIN, inventorySha256='a'*64, runtimeManifestSha256='b'*64)
        else:
            if mode == 'predecessor':
                owner = self.owner()
                owner._CandidateResume__nomination = nomination()
            elif retained:
                from tests.desktop.test_macos_candidate_carrier import retained_fixture
                selection, entries, _, *_ = retained_fixture()
                owner = retained_instance(selection)
                image, preview = dict(entries)[C.candidate.RETAINED_OBSERVER_IMAGE], None
                originals, selected, stage = mounted_fixture(owner.target)
                stage.xar_members = mock.Mock(return_value={'PackageInfo': b'info', 'Scripts': b'cpio'})
                stage.install_product_members.side_effect = AssertionError('flat observer must use the component parser')
                owner.selection = stage.source_build_selection(owner.target)
                stage.PRODUCER_DESCRIPTOR_BYTES, stage.PRODUCER_SIGNATURE_BYTES = 16384, 512
                stage.maintenance_producer_data.return_value['signingPolicies'][0]['policy']['leafCertificateSha1'] = 'e'*40
                owner._CandidateResume__members_document = R.canonical([
                    dict(name=name,bytes=len(body),sha256=R.sha(body)) for name,body in entries])
                owner._CandidateResume__image_document = R.canonical(
                    dict(name=C.candidate.RETAINED_OBSERVER_IMAGE,bytes=len(image),sha256=R.sha(image)))
                owner.admit_resources, owner.allocation_budget = mock.Mock(), mock.Mock()
                owner._resource_inputs = (0,0)
            else:
                with mock.patch.object(R.Resume, '__init__', return_value=None):
                    owner = C.CandidateResume(C.HELPER_ROOT, C.CANDIDATE_ROOT, Path('/inert'), None, None,
                                              nomination=nomination(), purpose=mode)
            row = dict(owner.nomination, package={'sha256':'c'*64}, inventorySha256='a'*64,
                       runtimeManifestSha256='b'*64)
            if retained:
                row.update({key:selected[key] for key in ('package','inventorySha256','runtimeManifestSha256')})
            owner._CandidateResume__artifact_admitted = owner._CandidateResume__source_loaded = True
            if not retained: owner._CandidateResume__preview_document = R.canonical(preview)
        owner.root, owner.work = C.HELPER_ROOT, Path('/inert')
        owner.run_id, owner.run_attempt, owner.private, owner.calls = '51', '2', {}, []
        owner.clock = R.Deadline(now=lambda: now[0])
        owner.environment = {'PATH':'/usr/bin:/bin:/usr/sbin:/sbin', 'TMPDIR':'/inert/'}
        owner.signing_identity = {'teamIdentifier':'INERTTEAM0', 'leafCertificateSha1':'e'*40}
        mount = owner.mount_path()
        info = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFDIR | 0o555,
            st_uid=501 if retained else 0, st_gid=20 if retained else 0, st_nlink=1, st_size=0, st_mtime_ns=0, st_ctime_ns=0)
        directory = {'fd':-1, 'identity':R.identity(info), 'path':owner.work}
        facts = (R.identity(info), 0, 'inert-filesystem')
        bodies = ({name:value[0] for name,value in originals.items()} if retained else
                  {'Install.pkg':b'P'*(65536+17), 'producer.json':b'inert-descriptor', 'producer.sig':b'inert-signature'})
        message = R.producer_message_data(bodies['producer.json'])
        owner.outer = SimpleNamespace(directories={Path('/'):directory},
            read=lambda entry: image if entry['path'].suffix == '.dmg' else message)
        owner.parent = directory
        def quote(book, operation, path, *args, **kwargs):
            if operation == 'directory': return directory
            return {'path':path, 'identity':(1,2)}, (bodies[path.name] if retained and book is mounted
                                                     else image if path.suffix == '.dmg' else message)
        owner.quota = SimpleNamespace(call=quote, check=lambda: None)
        held = tuple((name, {'kind':'file', 'path':mount/name, 'fd':100+index, 'closed':False,
            'identity':(1,index,stat.S_IFREG|0o444,0,0,1,len(body),0,0)}, body)
            for index,(name,body) in enumerate(bodies.items()))
        descriptors = {entry['fd']:(name,body) for name,entry,body in held}
        def finish():
            events.append('mounted-finish')
            for name,entry,body in held: entry.update(fd=None, closed=fault != 'mounted-close')
            return fault != 'mounted-close'
        mounted = SimpleNamespace(entries=[entry for name,entry,body in held], check=lambda: None,
            check_one=lambda entry: self.assertIs(entry['closed'], False), finish=finish)
        owner.fresh_book = lambda **kwargs: mounted
        owner.host = SimpleNamespace(filesystem=lambda fd: {'flags':0})
        owner.transport_facts = lambda entry: facts
        def roster(entry):
            if 'detach' in events:
                events.append('detach-post')
                if fault == 'detach-post': raise original_error
                return {}, facts
            return ({mount.name:(1,2,stat.S_IFDIR)} if 'attach' in events else {}), facts
        owner.transport_roster = roster
        owner.publish_image = mock.Mock()
        owner.publish_owned = mock.Mock()
        owner.fresh_directory = lambda parent, name: {'path':owner.work / name}
        def read_mounted(*args):
            if mode != 'fixed': owner._CandidateResume__binding = R.canonical(row)
            if mode == 'predecessor': owner._CandidateResume__mounted_reread_inputs = (mounted,held)
            return {name:(body,0o444) for name,body in bodies.items()}, row, {}, b'inert-inventory'
        if not retained:
            owner.read_mounted = read_mounted
            owner.prepare_readback = lambda *args: False if mode in ('acquire','acquire-restore','acquire-removal') else None
        request = 'f'*32
        ports = dict(distribution_mount_data=lambda *args: '/dev/inert',
            INSTALLATION_INVENTORY_NAME='install-inventory.json', INSTALL_ROOT=Path('/Applications'),
            APP_NAME='MobileReleaseKit.app', ENTRY_BUNDLE_ID='dev.inert.entry', BUNDLE_ID='dev.inert.payload',
            same_package_result_census=mock.Mock(side_effect=[{}, {request:'original'}, {request:'original'}]))
        if retained:
            vars(stage).update(ports); owner.stager = stage
        else: owner.stager = SimpleNamespace(**ports)
        def readback(args, original=None):
            events.append('readback')
            self.assertEqual(args.request_id, request)
            value = dict(requestId=request, originalInstallerReturnedZero=True, originalWriterJoined=fault != 'readback',
                sourceCommit=row['source'], completedPackageSha256=row['package']['sha256'],
                inventorySha256=row['inventorySha256'], runtimeManifestSha256=row['runtimeManifestSha256'])
            if retained:
                value.update(invocation='7'*32, installationMetadata=[{'instance':'8'*32}],
                    originalInstallerResult={'action':'fresh-install', 'stateSha256':'9'*64},
                    installerResultExport={'sha256':'a'*64})
            return value
        if retained: owner.stager.observation_command = mock.Mock(side_effect=readback)
        else: owner.observe_installation = readback
        def run_owned(argv, **kwargs):
            role = owner.calls[-1]['role']
            events.append(role); native_calls.append((role, argv, kwargs))
            if fault == role + '-unknown': raise original_error
            code = 16 if role == 'detach' and fault in ('detach16','reread-bytes-detach16') else 1 if fault == role else 0
            stdout = (b'-----BEGIN PUBLIC KEY-----\ninert\n-----END PUBLIC KEY-----\n' if role == 'producer-key'
                      else b'Verified OK\n' if role == 'producer-signature' else b'')
            if fault == role + '-stdout': stdout = b'inert-not-empty'
            stderr = b'inert-not-empty' if fault == role + '-stderr' else b''
            if role == 'detach' and fault == 'work-deadline': now[0] = owner.clock.work + 1
            return subprocess.CompletedProcess(argv, code, stdout, stderr)
        owner.owner = SimpleNamespace(run_owned=run_owned)
        retained_post = R.retained_image_post
        def byte_post(book, entry, body, clock):
            if book is not mounted:
                events.append('mounted-post')
                return
            self.assertIs(entry, next(item for item in mounted.entries if item is entry))
            retained_post(book,entry,body,clock)
        def pread(fd, count, offset):
            name,body = descriptors[fd]
            self.assertLessEqual(count,65536)
            self.assertIs(owner.clock.finality,False)
            self.assertIn('readback', events)
            self.assertNotIn('mounted-finish',events)
            events.append(('reread',name,count,offset))
            if fault == 'reread-unknown': raise original_error
            if name == 'Install.pkg':
                if fault in ('reread-bytes','reread-bytes-detach16') and offset == 65536: return b'X'*count
                if fault == 'reread-eof' and offset == len(body): return b'X'
                if fault == 'reread-deadline': now[0] = owner.clock.work + 1
            return body[offset:offset+count]
        with ExitStack() as patches:
            patches.enter_context(mock.patch.dict(R.STATE, phase='admission', firstFailurePhase=None))
            patches.enter_context(mock.patch.object(R.os, 'fstat', return_value=info))
            def observed_stat(name, **kwargs):
                if retained and name in bodies:
                    return SimpleNamespace(st_mode=stat.S_IFREG|0o444, st_size=len(bodies[name]), st_uid=0, st_gid=0)
                return info
            patches.enter_context(mock.patch.object(R.os, 'stat', side_effect=observed_stat))
            patches.enter_context(mock.patch.object(R.os, 'fstatvfs', return_value=SimpleNamespace(f_flag=0)))
            patches.enter_context(mock.patch.object(R.os, 'listdir', return_value=['Install.pkg','producer.json','producer.sig']))
            patches.enter_context(mock.patch.object(R, 'mount_data'))
            patches.enter_context(mock.patch.object(R.os, 'pread', side_effect=pread))
            patches.enter_context(mock.patch.object(R, 'retained_image_post', side_effect=byte_post))
            yield owner, image, preview, events, native_calls, original_error

    def test_retained_actual_install_consume_and_receipt_require_original_finality(self):
        faults = (None, 'pre-source', 'post-source', 'producer-key', 'producer-signature',
            'producer-signature-stdout', 'producer-signature-stderr', 'request-before', 'request-after',
            'installer', 'readback', 'not-fresh', 'entry-signature', 'payload-signature', 'mounted-close',
            'detach16', 'detach-unknown', 'detach-post', 'call-capture', 'retire', 'close', 'final-close')
        for fault in faults:
            with self.subTest(fault=fault), self.scheduled_install('retained-observer', fault) as (owner,image,preview,events,calls,original):
                self.assertIsNone(preview)
                owner.helper_source, owner.helper_tree = 'd'*40, 'e'*40
                owner.quota.reserved = 76
                owner.quota.finish = mock.Mock(side_effect=[True,False] if fault == 'final-close' else None,
                                               return_value=fault != 'close')
                owner.acquire_candidate = mock.Mock(return_value={C.candidate.RETAINED_OBSERVER_IMAGE:image})
                source_calls = []
                def sources():
                    source_calls.append(len(calls))
                    events.append('source-post' if len(source_calls) == 2 else 'source-pre')
                    if fault == ('post-source' if len(source_calls) == 2 else 'pre-source'): raise original
                    if len(source_calls) == 2 and fault == 'call-capture': owner.calls[-1]['capturesSettled'] = False
                owner.verify_sources = mock.Mock(side_effect=sources)
                def retire():
                    events.append('retire')
                    if fault == 'retire': raise original
                owner.retire = mock.Mock(side_effect=retire)
                if fault == 'request-before': owner.stager.same_package_result_census.side_effect = [{'b'*32:'old'}]
                if fault == 'request-after': owner.stager.same_package_result_census.side_effect = [{}, {}]
                if fault == 'not-fresh':
                    readback = owner.stager.observation_command.side_effect
                    def old_action(args):
                        value = readback(args); value['originalInstallerResult']['action'] = 'same-package'
                        return value
                    owner.stager.observation_command.side_effect = old_action
                with mock.patch.object(owner, 'retained_observer_receipt', wraps=owner.retained_observer_receipt) as receipt, \
                        mock.patch.object(C.candidate, 'candidate_preview_data') as old_preview:
                    if fault is None:
                        value = owner.consume(0,0)
                        self.assertEqual(value['scope'],'retained-observer-fresh-install')
                        self.assertEqual(value['nomination'],owner.nomination)
                        self.assertEqual(value['nomination']['runId'],'42')
                        self.assertEqual((value['consumerRunId'],value['consumerRunAttempt']),('51','2'))
                        self.assertEqual(value['consumerWorkDirectory'],[1,2,501])
                        self.assertEqual(value['freshInstall'],dict(requestId='f'*32,invocation='7'*32,instance='8'*32,
                            stateSha256='9'*64,resultSha256='a'*64))
                        self.assertEqual(value['image'],dict(name=C.candidate.RETAINED_OBSERVER_IMAGE,bytes=len(image),sha256=R.sha(image)))
                        self.assertEqual(value['release']['sourceCommit'],owner.nomination['source'])
                        self.assertFalse(value['productReady'] or value['p0Qualified'] or value['uiQualified'])
                        self.assertNotIn('consumerReturnedZero',value)  # A record cannot prove its caller's future return.
                        owner.stager.xar_members.assert_called_once_with(b'package', allocation_budget=owner.allocation_budget)
                        owner.stager.install_product_members.assert_not_called()
                        receipt.assert_called_once_with()
                        self.assertEqual(owner.quota.finish.call_count,2)
                    else:
                        with self.assertRaises((R.Refused, RuntimeError)): owner.consume(0,0)
                        self.assertEqual(receipt.call_count,int(fault == 'final-close'))
                    old_preview.assert_not_called()
                roles = [role for role,argv,kwargs in calls]
                self.assertLessEqual(roles.count('installer'),1)
                no_detach = ('pre-source','request-after','installer','readback','not-fresh','mounted-close')
                self.assertEqual(roles.count('detach'),0 if fault in no_detach else 1)
                if fault is None:
                    self.assertEqual(roles,['attach','producer-key','producer-signature','installer',
                                           'entry-signature','payload-signature','detach'])
                    self.assertLess(events.index('producer-signature'),events.index('installer'))
                    self.assertLess(events.index('installer'),events.index('readback'))
                    self.assertLess(events.index('readback'),events.index('entry-signature'))
                    self.assertLess(events.index('payload-signature'),events.index('mounted-finish'))
                    self.assertLess(events.index('mounted-finish'),events.index('detach'))
                    self.assertLess(events.index('detach-post'),events.index('source-post'))
                    self.assertLess(events.index('source-post'),events.index('retire'))
                for role,argv,kwargs in calls:
                    if role == 'installer':
                        self.assertEqual(argv,['/usr/bin/sudo','-n','--','/usr/sbin/installer','-pkg',
                            str(owner.mount_path()/'Install.pkg'),'-target','/','-dumplog','-verboseR'])
                        self.assertEqual(kwargs['timeout'],123)
                        self.assertFalse(kwargs['cleanup'])
                    if role == 'detach':
                        self.assertEqual(argv,['/usr/bin/hdiutil','detach','/dev/inert'])
                        self.assertEqual(kwargs['timeout'],30)
                        self.assertTrue(kwargs['cleanup'])
                self.assertIsNone(C._PREDECESSOR_DETACH)
                if owner._CandidateResume__installation_entered:
                    count = len(calls)
                    with self.assertRaisesRegex(R.Refused,'candidate-install-order'): owner.install_image(image,None)
                    self.assertEqual(len(calls),count)

    def test_retained_plain_image_and_signed_current_source_guards_precede_installer(self):
        for fault in ('preview','image','sourceCommit','packageVersion','packageSha256','inventory-codec','package-bound'):
            with self.subTest(fault=fault), self.scheduled_install('retained-observer') as (owner,image,_,events,calls,original):
                if fault in ('sourceCommit','packageVersion','packageSha256'):
                    owner.stager.maintenance_producer_data.return_value['releaseSet']['current'][fault] = 'changed'
                if fault == 'inventory-codec': owner.stager.observation_inventory_bytes.side_effect = original
                with ExitStack() as patches:
                    if fault == 'package-bound':
                        stat_port = R.os.stat.side_effect
                        def oversized(name, **kwargs):
                            value = stat_port(name,**kwargs)
                            if name == 'Install.pkg': value.st_size = R.LIMIT+1
                            return value
                        patches.enter_context(mock.patch.object(R.os,'stat',side_effect=oversized))
                    with self.assertRaises((R.Refused,RuntimeError)):
                        owner.install_image(b'other-image' if fault == 'image' else image, {} if fault == 'preview' else None)
                roles = [role for role,argv,kwargs in calls]
                self.assertEqual(roles, [] if fault in ('preview','image') else ['attach','detach'])
                owner.stager.observation_command.assert_not_called()
                self.assertIsNone(owner._CandidateResume__observer_product)
                with self.assertRaisesRegex(R.Refused,'retained-observer-signed-product-missing'):
                    owner.retained_observer_receipt()

    def test_only_predecessor_moves_the_exact_pair_after_first_detach(self):
        for mode in ('predecessor','fixed',*C.PURPOSES):
            with self.subTest(mode=mode), self.scheduled_install(mode) as (owner,image,preview,events,calls,_):
                self.assertIsNone(owner.install_image(image, preview))
                roles = [role for role,argv,kwargs in calls]
                expected = ['attach','producer-key','producer-signature']
                if mode not in ('acquire','acquire-restore','acquire-removal'):
                    expected += ['installer']
                    expected += (['detach','entry-signature','payload-signature'] if mode == 'predecessor'
                                 else ['entry-signature','payload-signature','detach'])
                    self.assertLess(events.index('producer-signature'), events.index('installer'))
                    self.assertLess(events.index('installer'), events.index('readback'))
                    self.assertLess(events.index('readback'), events.index('mounted-finish'))
                else:
                    expected += ['detach']
                self.assertEqual(roles, expected)
                self.assertTrue(owner.mount_detached)
                self.assertLess(events.index('mounted-finish'), events.index('detach'))
                if mode == 'predecessor':
                    self.assertEqual(owner._CandidateResume__installed_signature_state, 'verified')
                    self.assertEqual(owner._CandidateResume__mounted_reread_state, 'verified')
                    self.assertIsNone(owner._CandidateResume__mounted_reread_inputs)
                    self.assertLess(events.index('readback'), events.index('mounted-post', events.index('readback')))
                    self.assertLess(events.index('detach-post'), events.index('entry-signature'))
                    self.assertEqual(C._PREDECESSOR_DETACH['outcome'], 'detach0')
                    self.assertTrue(C._PREDECESSOR_DETACH['finalMountedRereadKnown'])
                    rereads = [event for event in events if type(event) is tuple and event[0] == 'reread']
                    self.assertEqual(rereads, [('reread','Install.pkg',65536,0),('reread','Install.pkg',17,65536),
                        ('reread','Install.pkg',1,65553),('reread','producer.json',16,0),('reread','producer.json',1,16),
                        ('reread','producer.sig',15,0),('reread','producer.sig',1,15)])
                    self.assertLess(events.index('mounted-post',events.index('readback')),events.index(rereads[0]))
                    self.assertEqual(events[events.index(rereads[-1])+1], 'mounted-finish')
                else:
                    self.assertFalse(any(type(event) is tuple and event[0] == 'reread' for event in events))
                for role,argv,kwargs in calls:
                    self.assertEqual(kwargs['environ'], owner.environment)
                    self.assertEqual(kwargs['cwd'], owner.work)
                    if role == 'detach':
                        self.assertEqual(argv, ['/usr/bin/hdiutil','detach','/dev/inert'] + (['-verbose'] if mode == 'predecessor' else []))
                        self.assertEqual(kwargs['timeout'], 30)
                        self.assertIs(kwargs['cleanup'], True)
                    if role in ('entry-signature','payload-signature'):
                        identifier = 'dev.inert.entry' if role == 'entry-signature' else 'dev.inert.payload'
                        requirement = ('=identifier "' + identifier + '" and anchor apple generic'
                            ' and certificate 1[field.1.2.840.113635.100.6.2.6] exists'
                            ' and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
                            ' and certificate leaf[subject.OU] = "INERTTEAM0" and certificate leaf = H"' + 'e'*40 + '"')
                        path = '/Applications/MobileReleaseKit.app' + ('' if role == 'entry-signature' else '/Contents/Helpers/MobileReleaseKitPayload.app')
                        self.assertEqual(argv, ['/usr/bin/codesign','--verify','--strict','--test-requirement',requirement,path])
                        self.assertEqual(kwargs['timeout'], 30)
                        self.assertIs(kwargs['cleanup'], False)
                if mode == 'predecessor':
                    with self.assertRaisesRegex(R.Refused, 'candidate-install-order'): owner.install_image(image, preview)
                    with self.assertRaisesRegex(R.Refused, 'candidate-predecessor-signature-order'): owner.verify_installed_signatures()
                    self.assertEqual(len(calls), 7)

    def test_predecessor_detach_and_required_signature_failures_never_succeed_or_retry(self):
        for fault in ('installer','readback','mounted-close','detach16','detach-unknown','detach-post','work-deadline',
                      'entry-signature','payload-signature','entry-signature-unknown',
                      'entry-signature-stdout','entry-signature-stderr','payload-signature-stdout','payload-signature-stderr'):
            with self.subTest(fault=fault), self.scheduled_install(fault=fault) as (owner,image,preview,events,calls,original):
                with self.assertRaises((R.Refused, RuntimeError)) as caught: owner.install_image(image, preview)
                if fault in ('detach-unknown','detach-post','entry-signature-unknown'):
                    self.assertIs(caught.exception, original)
                roles = [role for role,argv,kwargs in calls]
                self.assertEqual(roles.count('detach'), 0 if fault in ('installer','readback','mounted-close') else 1)
                signatures = [role for role in roles if role in ('entry-signature','payload-signature')]
                self.assertEqual(signatures, ['entry-signature','payload-signature'] if fault.startswith('payload-signature')
                                 else ['entry-signature'] if fault.startswith('entry-signature') else [])
                self.assertNotEqual(owner._CandidateResume__installed_signature_state, 'verified')
                if signatures:
                    self.assertTrue(owner.mount_detached)
                    self.assertLess(events.index('detach-post'), events.index('entry-signature'))
                report = C.failure_data(caught.exception)
                self.assertNotIn('installedSignaturesVerified', report)
                if C._PREDECESSOR_DETACH is not None:
                    self.assertEqual(report['installedSignatureCheckOrder'], 'after-first-detach0')
                    self.assertFalse(report['packageInstallScheduleEqual'])
                if fault == 'detach16':
                    self.assertEqual(report['reason'], 'resume-original-detach')
                    self.assertEqual(report['detachObservation']['outcome'], 'detach16')

    def test_final_reread_failure_keeps_primary_and_cannot_reach_signature_or_success(self):
        for fault in ('reread-bytes','reread-eof','reread-unknown','reread-deadline','reread-bytes-detach16'):
            with self.subTest(fault=fault), self.scheduled_install(fault=fault) as (owner,image,preview,events,calls,original):
                with self.assertRaises((R.Refused,RuntimeError)) as caught: owner.install_image(image,preview)
                if fault == 'reread-unknown': self.assertIs(caught.exception,original)
                self.assertEqual(owner._CandidateResume__mounted_reread_state,'entered')
                self.assertIsNone(owner._CandidateResume__mounted_reread_inputs)
                self.assertEqual(owner._CandidateResume__installed_signature_state,'deferred')
                self.assertEqual([role for role,argv,kwargs in calls], ['attach','producer-key','producer-signature','installer','detach'])
                self.assertEqual(events.count('mounted-finish'),1)
                self.assertLess(events.index('mounted-finish'),events.index('detach'))
                report = C.failure_data(caught.exception)
                self.assertFalse(report['detachObservation']['finalMountedRereadKnown'])
                self.assertNotIn('finalMountedRereadVerified',report)
                self.assertNotIn('installedSignaturesVerified',report)
                if fault == 'reread-bytes-detach16':
                    self.assertEqual(report['reason'],'resume-image-retained-post')
                    self.assertEqual(report['detachObservation']['outcome'],'detach16')
                    self.assertIn('resume-detach-finality-failed',caught.exception.__notes__)

    def test_predecessor_receipt_cannot_promote_pending_or_failed_signatures(self):
        originals, row, stage = mounted_fixture('aarch64-apple-darwin')
        result, inventory = R.mounted_data(originals, row, row['target'], stage, candidate=True)
        for state,reread in ((None,'verified'),('deferred','verified'),('entered','verified'),
                             ('verified',None),('verified','entered'),('verified','verified')):
            with self.subTest(state=state,reread=reread):
                owner = self.owner()
                owner._CandidateResume__nomination = nomination()
                owner._CandidateResume__source_loaded = True
                owner._CandidateResume__installed_signature_state = state
                owner._CandidateResume__mounted_reread_state = reread
                owner._CandidateResume__detach_observation = {'outcome':'detach0'}
                owner.helper_source, owner.helper_tree, owner.run_id, owner.run_attempt = 'd'*40, 'e'*40, '51', '2'
                owner.quota = SimpleNamespace(reserved=0, finish=mock.Mock(return_value=True))
                owner.clock = SimpleNamespace(finality=False, check=mock.Mock())
                owner.point = mock.Mock(); owner.admit_resources = mock.Mock(); owner.retire = mock.Mock()
                owner.verify_sources = mock.Mock()
                owner.acquire_candidate = mock.Mock(return_value={'PREVIEW.json':b'inert','MobileReleaseKit.dmg':b'inert'})
                owner.install_image = lambda *args: owner.prepare_readback(result, inventory)
                owner.installer_zero = owner.readback_known = owner.mount_detached = True
                owner.calls = [{'returned':True,'capturesSettled':True}]
                with mock.patch.object(C.candidate, 'candidate_preview_data', return_value={}):
                    if state != 'verified':
                        with self.assertRaisesRegex(R.Refused, 'candidate-predecessor-installed-signatures'): owner.consume(0,0)
                    elif reread != 'verified':
                        with self.assertRaisesRegex(R.Refused, 'candidate-predecessor-reread-known'): owner.consume(0,0)
                    else:
                        report = owner.consume(0,0)
                        self.assertTrue(report['installedSignaturesVerified'])
                        self.assertEqual(report['installedSignatureCheckOrder'], 'after-first-detach0')
                        self.assertTrue(report['finalMountedRereadVerified'])
                        self.assertEqual(report['finalMountedRereadOrder'],'after-readback-before-mounted-closes')
                        self.assertFalse(report['packageInstallScheduleEqual'] or report['p0Qualified'] or report['productReady'])
                        self.assertLessEqual(len(R.canonical(report)), C.PREDECESSOR_METADATA_LIMIT)

    def test_fixed_dispatch_and_arm_only_context(self):
        env = self.environment()
        context = C.context_data(env, C.HELPER_ROOT, 'arm64')
        self.assertEqual(context['helperSource'], env['GITHUB_SHA'])
        for key, value in (('GITHUB_EVENT_NAME', 'push'), ('MRK_CANDIDATE_MODE', 'restore'),
            ('GITHUB_REF', 'refs/heads/' + C.BRANCH), ('GITHUB_SHA', 'e'*40),
            ('GITHUB_WORKFLOW_REF', env['GITHUB_WORKFLOW_REF'] + '-other'),
            ('RUNNER_ENVIRONMENT', 'self-hosted'), ('GITHUB_WORKSPACE', str(C.HELPER_ROOT))):
            with self.subTest(key=key), self.assertRaises(R.Refused):
                C.context_data(dict(env, **{key:value}), C.HELPER_ROOT, 'arm64')
        with self.assertRaises(R.Refused):
            C.context_data(dict(env, MRK_MACOS_TARGET='x86_64-apple-darwin', RUNNER_ARCH='X64'),
                           C.HELPER_ROOT, 'x86_64')

    def test_nomination_is_separate_exact_public_p0_original(self):
        import json
        body = (ROOT / C.PREDECESSOR_SELECTION_PATH).read_bytes()
        selected = C.selection_data(body, 'aarch64-apple-darwin')
        predecessor = json.loads((ROOT / 'desktop/macos-installed-inputs/update-predecessors.json').read_bytes())['targets']['aarch64-apple-darwin']
        self.assertEqual({key:value for key,value in selected.items() if key not in ('tree','target')},
                         {key:predecessor[key] for key in selected if key not in ('tree','target')})
        self.assertEqual(selected['source'], 'bf9d397bde641aae4b4cd205f3c962e899557650')
        self.assertEqual(selected['tree'], 'f3d2f9117d1f29e080c5138fa9675426fb79e247')
        self.assertEqual(selected['artifactId'], '12157830080')
        self.assertEqual(set(json.loads(body)['targets']), {'aarch64-apple-darwin'})
        owner = self.owner()
        owner.source = mock.Mock(return_value=body)
        owner.load_nomination('aarch64-apple-darwin')
        self.assertEqual(owner.nomination, selected)
        owner.source.assert_called_once_with(C.PREDECESSOR_SELECTION_PATH, 8192)
        with self.assertRaises(R.Refused): owner.load_nomination('aarch64-apple-darwin')
        self.assertEqual(owner.source.call_count, 1)
        for failure in (FileNotFoundError('inert missing'), R.Refused('inert custody')):
            owner = self.owner(); owner.source = mock.Mock(side_effect=failure)
            with self.assertRaises(type(failure)) as caught: owner.load_nomination('aarch64-apple-darwin')
            self.assertIs(caught.exception, failure)
            owner.source.assert_called_once_with(C.PREDECESSOR_SELECTION_PATH, 8192)
        owner = self.owner(); owner.source = mock.Mock()
        with self.assertRaises(R.Refused): owner.load_nomination('x86_64-apple-darwin')
        owner.source.assert_not_called()

    def test_only_no_argument_plain_install_is_admitted(self):
        with self.assertRaises(R.Refused): self.owner(nomination=nomination())
        with mock.patch.dict(C.os.environ, self.environment(), clear=True):
            for purpose in C.PURPOSES[1:]:
                with self.subTest(purpose=purpose), mock.patch.object(C, 'entry_context') as entry:
                    with self.assertRaises(R.Refused): C.main(purpose)
                    entry.assert_not_called()
                    with self.assertRaises(R.Refused): self.owner(purpose=purpose)
            stop = RuntimeError('inert stop before any native/source acquisition')
            with mock.patch.object(C, 'entry_context', side_effect=stop) as entry:
                with self.assertRaises(RuntimeError) as caught: C.main()
                self.assertIs(caught.exception, stop)
                entry.assert_called_once_with(())
            with mock.patch.object(C, 'entry_context', return_value={}), mock.patch.object(R, 'host_read') as read:
                for purpose in ('prepare-restore', 'restore-baseline', 'restore-chain'):
                    with self.assertRaises(R.Refused): C.fixture_main(purpose)
                for phase in C.REMOVAL_PHASES:
                    with self.assertRaises(R.Refused): C.removal_main(phase)
                read.assert_not_called()

    def test_same_original_detach_is_verbose_once_and_result_is_unchanged(self):
        import subprocess
        argv = ['/usr/bin/hdiutil', 'detach', '/dev/disk9s1']
        for code, outcome in ((0,'detach0'), (16,'detach16'), (1,'other-return')):
            owner = self.owner()
            result = subprocess.CompletedProcess(argv + ['-verbose'], code,
                b'Unmount: PRIVATE-NATIVE-PATH\n', b'hdiutil: detach failed - Resource busy\n')
            with mock.patch.object(R.Resume, 'command', return_value=result) as native:
                self.assertIs(owner.command('detach', argv, 30), result)
                native.assert_called_once_with('detach', argv + ['-verbose'], 30)
                self.assertEqual(argv, ['/usr/bin/hdiutil', 'detach', '/dev/disk9s1'])
                with self.assertRaises(R.Refused): owner.command('detach', argv, 30)
                self.assertEqual(native.call_count, 1)
            report = C.failure_data(R.Refused('resume-original-detach'))
            self.assertEqual(report['detachObservation']['outcome'], outcome)
            self.assertTrue(report['detachObservation']['returned'])
            self.assertTrue(report['detachObservation']['installerReturnedZero'])
            self.assertTrue(report['detachObservation']['readbackKnown'])
            self.assertEqual(report['detachObservation']['textHints'], ['resource-busy-text','unmount-text'])
            self.assertFalse(report['packageInstallScheduleEqual'])
            self.assertEqual(report['installedSignatureCheckOrder'], 'after-first-detach0')
            self.assertNotIn('installedSignaturesVerified', report)
            self.assertFalse(report['cleanupAuthorized'])
            self.assertNotIn('PRIVATE-NATIVE-PATH', repr(report))

    def test_unknown_original_and_diagnostic_error_never_replace_or_retry(self):
        import subprocess
        argv = ['/usr/bin/hdiutil', 'detach', '/dev/disk9s1']
        owner = self.owner(); failure = RuntimeError('inert original unknown')
        with mock.patch.object(R.Resume, 'command', side_effect=failure) as native:
            with self.assertRaises(RuntimeError) as caught: owner.command('detach', argv, 30)
            self.assertIs(caught.exception, failure)
            self.assertEqual(C._PREDECESSOR_DETACH['outcome'], 'unknown')
            self.assertFalse(C._PREDECESSOR_DETACH['returned'])
            with self.assertRaises(R.Refused): owner.command('detach', argv, 30)
            self.assertEqual(native.call_count, 1)
        owner = self.owner(); result = subprocess.CompletedProcess(argv + ['-verbose'],16,b'',b'')
        with mock.patch.object(R.Resume, 'command', return_value=result) as native, \
                mock.patch.object(C, 'predecessor_detach_data', side_effect=RuntimeError('inert parser fault')):
            self.assertIs(owner.command('detach', argv, 30), result)
            self.assertEqual(C._PREDECESSOR_DETACH['outcome'], 'detach16')
            native.assert_called_once_with('detach', argv + ['-verbose'], 30)
        for bad in (argv + ['-force'], ['/usr/bin/sudo', 'hdiutil', 'detach']):
            with mock.patch.object(R.Resume, 'command') as native:
                with self.assertRaises(R.Refused): self.owner().command('detach', bad, 30)
                native.assert_not_called()

    def test_nonselected_calls_keep_original_argv_and_no_observation(self):
        original = object(); argv = ['/inert/original']; environment = {'inert':'value'}
        for owner, role in ((instance(),'detach'), (self.owner(),'installer')):
            with mock.patch.object(R.Resume, 'command', return_value=original) as native:
                self.assertIs(owner.command(role, argv, 123, env=environment), original)
                native.assert_called_once_with(role, argv, 123, env=environment)
        self.assertIsNone(C._PREDECESSOR_DETACH)

    def test_projection_is_bounded_literal_both_streams_only(self):
        from desktop.tools import macos_android_helper_package as H
        cases = ((b'',b'',[]), (b'RESOURCE BUSY; UNMOUNT; EJECT',b'DISSENT',
            ['resource-busy-text','unmount-text','eject-text','dissent-text']),
            (b'resource',b' busy',[]), (b'x'*65536,b'',[]),
            (b'x'*65536,b'x',None), ('not bytes',b'hdiutil: detach failed - Resource busy\n',None),
            (b'',b'hdiutil: detach failed - Permission denied\n',[]), (b'',None,None),
            (b'',b'\n'.join((b'hdiutil: detach failed - Resource busy',b'hdiutil: detach failed - No such device')),
             ['resource-busy-text']))
        for stdout,stderr,hints in cases:
            with self.subTest(hints=hints):
                self.assertEqual(C.predecessor_detach_data(stdout,stderr),
                                 {'stderr':H.distribution_detach_stderr(stderr),'textHints':hints})
        self.assertEqual(R.MAX_ORIGINALS,96)
        clock = R.Deadline(now=lambda:1)
        self.assertEqual(clock.deadline-clock.started,600_000_000_000)
        self.assertEqual(clock.deadline-clock.work,60_000_000_000)
