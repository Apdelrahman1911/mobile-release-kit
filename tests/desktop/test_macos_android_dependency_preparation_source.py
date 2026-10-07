"""SOURCE plus inert SDK parser/loader and tiny nonroot original-FD regressions.

Never native SDK observation, vendor execution, licence acceptance or acquisition.
"""
import ast
import hashlib
import json
import importlib.util
import os
import plistlib
import stat
import sys
import tempfile
import types
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

def fixture_module(relative, name):
    # The isolated validation projection authenticates these readonly SOURCE
    # originals. Both fixtures have inert top levels and guarded native main.
    if name in sys.modules:
        raise AssertionError('fixture module collision')
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    if spec is None or spec.loader is None:
        raise AssertionError('fixture module specification')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if name in sys.modules:
        raise AssertionError('unregistered fixture changed registry')
    return module


class MacAndroidPreparationSourceTests(unittest.TestCase):
    def test_fixed_preparation_owner_resources_scope_and_budgets(self):
        source = (ROOT / 'desktop/tools/macos_android_dependency_preparation.py').read_text()
        tree = ast.parse(source)
        constants = {n.targets[0].id: ast.literal_eval(n.value) for n in tree.body
                     if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                     and n.targets[0].id in ('ARCHIVES', 'PINS', 'RESOURCES', 'SDK_CURRENT_USE', 'RUN_SCOPE')}
        self.assertIsNone(constants['SDK_CURRENT_USE'])
        self.assertEqual(constants['RUN_SCOPE'], 'observe-sdk')
        self.assertEqual([r['role'] for r in constants['ARCHIVES']], ['jdk', 'sdk-platform', 'sdk-build-tools', 'gradle', 'aapt2'])
        self.assertEqual(sum(r['bytes'] for r in constants['ARCHIVES']), 469391018)
        for path, pin in constants['RESOURCES'].items():
            raw = (ROOT / path).read_bytes()
            self.assertEqual([len(raw), hashlib.sha256(raw).hexdigest()], pin)
        for text in ('N.NormalPhase(', 'N.load_normal_owner(SOURCE)', 'C.compile_archive(',
                     'capture.consume_rows(self.terminal_row)', 'self.verify_binding()',
                     "'unsupported-vendor-alias'", 'os.O_NOFOLLOW', 'os.O_EXCL',
                     "'--dependency-verification', 'strict', '--write-locks', ':app:bundleRelease'",
                     "'--max-workers=2'", "'-Xmx2048m'", 'PHASE_SECONDS = 1200',
                     'ACQUISITION_SECONDS = 900', "command, 900, 2 << 20", 'READ_BYTES = 8 << 30',
                     'shutil.rmtree.avoids_symlink_attacks', 'shutil.rmtree(leaf, dir_fd=fd)'):
            self.assertIn(text, source)
        for text in ('--write-verification-metadata', 'sdkmanager', 'subprocess.run(', 'extractall(', 'gradle --stop'):
            self.assertNotIn(text, source)
        workflow = (ROOT / '.github/workflows/desktop-macos-android-dependencies.yml').read_text()
        self.assertIn('branches: [verify/desktop-macos-android-dependencies]', workflow)
        self.assertIn('runs-on: macos-26', workflow)
        self.assertIn('timeout-minutes: 14', workflow)
        self.assertIn('2+3+3+1+1+2=12', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('python-version: \'3.14.7\'', workflow)
        self.assertIn("macos_android_dependency_preparation.py observe-sdk", workflow)
        self.assertNotIn("macos_android_dependency_preparation.py prepare-a", workflow)
        self.assertIn("MRK_PREPARATION_EVIDENCE_UPLOAD", source)
        self.assertNotIn('secrets.', workflow)
        self.assertNotIn('workflow_dispatch:', workflow)
        self.assertNotIn('setup-node', workflow)
        self.assertNotIn('ci_foundation.py', workflow)
        self.assertNotIn('wrapper.stdout\n', workflow[workflow.index('          path: |'):])

    def test_observe_sdk_real_metadata_and_post_parse_failure_never_grant_authority(self):
        helper = fixture_module('desktop/tools/macos_android_dependency_preparation.py', '_mrk_sdk_observe_data')
        transport = fixture_module('desktop/tools/macos_android_supplier_preparation.py', '_mrk_sdk_properties_data')
        public_xml = {}
        for relative, expected in (
                ('desktop/macos-installed-inputs/android-sdk/platform-35-package.xml',
                 (17832, '385364dad6ba50838ec90abc8e4593976e0e0c54c87cf703857ba0a1aad63fe2')),
                ('desktop/macos-installed-inputs/android-sdk/build-tools-35-package.xml',
                 (17719, '6f7a9969f1bb25e39ae22fa5690b878e6806217453acf3b534712fb3a76ad1d4'))):
            body = (ROOT / relative).read_bytes()
            self.assertEqual((len(body), hashlib.sha256(body).hexdigest()), expected)
            public_xml[relative.rsplit('/', 1)[1]] = body
        sdk = '/Users/runner/Library/Android/sdk'
        system = '/System/Library/CoreServices/SystemVersion.plist'
        platform_properties = sdk + '/platforms/android-35/source.properties'
        platform_xml = sdk + '/platforms/android-35/package.xml'
        build_xml = sdk + '/build-tools/35.0.0/package.xml'
        receipt = sdk + '/licenses/android-sdk-license'
        selected_id = '24333f8a63b6825ea9c5514f83c2829b004d1fee'
        bodies = {
            system: plistlib.dumps({'ProductVersion': '26.0.1'}),
            receipt: (selected_id + '\n').encode(),
            platform_properties: b'Pkg.Revision=2\nAndroidVersion.ApiLevel=35\n',
            platform_xml: public_xml['platform-35-package.xml'],
            sdk + '/build-tools/35.0.0/source.properties': b'Pkg.Revision=35.0.0\n',
            build_xml: public_xml['build-tools-35-package.xml'],
        }
        expected_reads = [(system, 65536), (receipt, 4096), (platform_properties, 65536),
                          (platform_xml, 65536), (sdk + '/build-tools/35.0.0/source.properties', 65536),
                          (build_xml, 65536)]
        original = helper.N, helper.P, helper.os, helper.read, helper.publish_json
        environment = {'GITHUB_SHA': 'a' * 40, 'MRK_PROVISIONED_SDK_ROOT': sdk,
                       'ImageOS': 'macos26', 'ImageVersion': '20261005.1'}
        try:
            def invoke(changes=None, *, late=None, publication=None):
                frames = dict(bodies)
                frames.update(changes or {})
                reads, publications, clocks = [], [], []
                class Clock:
                    def __init__(clock, seconds):
                        self.assertEqual(seconds, 30)
                        clock.failed = False
                        clock.finished = False
                        clocks.append(clock)
                    def check(clock):
                        # All six fake original reads have returned. This is the
                        # final check AFTER the real parser stages positivity.
                        if late is not None and len(reads) == 6:
                            raise late
                        if clock.failed:
                            raise helper.Refused('inert-clock-already-failed')
                    def finish(clock):
                        clock.check()
                        clock.finished = True
                def readonly(path, limit, *, clock):
                    clock.check()
                    key = str(path)
                    self.assertEqual((key, limit), expected_reads[len(reads)])
                    reads.append((key, limit))
                    raw = frames[key]
                    if isinstance(raw, BaseException):
                        raise raw
                    self.assertLessEqual(len(raw), limit)
                    state = (1, len(reads), stat.S_IFREG | 0o444, 0 if key == system else os.getuid(),
                             os.getgid(), 1, len(raw), 1, 1)
                    return raw, state
                def publish(private, name, value):
                    self.assertIs(private, admitted)
                    self.assertEqual(name, 'sdk-observation.json')
                    if publication is not None:
                        raise publication
                    raw = helper.encoded(value)
                    self.assertLessEqual(len(raw), 16384)
                    publications.append(json.loads(raw))
                admitted = object()  # Explicit DATA adapter, not a Mac work receipt.
                helper.N = types.SimpleNamespace(PhaseClock=Clock)
                helper.P = transport  # Real properties decoder; no hash/parser stubs.
                helper.os = types.SimpleNamespace(**dict(vars(os), environ=dict(environment)))
                helper.read, helper.publish_json = readonly, publish
                returned, failure = None, None
                try:
                    returned = helper.observe_sdk_current_use(Path('/case/inert-output'), private=admitted)
                except BaseException as error:
                    failure = error
                return returned, failure, reads, publications, clocks

            returned, failure, reads, publications, clocks = invoke()
            self.assertIsNone(failure)
            self.assertEqual(reads, expected_reads)
            self.assertEqual(len(publications), 1)
            self.assertEqual(returned, publications[0])
            self.assertEqual(returned['status'], 'observed-not-admitted')
            self.assertTrue(returned['originalsClosed'])
            self.assertFalse(returned['acceptancePerformed'])
            self.assertEqual(returned['existingSelectedReceiptId'], selected_id)
            self.assertEqual(returned['licenseDefinitionSha256'],
                             'aaf80cd0aee7e569ffa8a4be1b61189c0fefccf23068e38dfafe336289b8c723')
            self.assertEqual([p['package'] for p in returned['packages']],
                             ['platforms;android-35', 'build-tools;35.0.0'])
            self.assertEqual(returned['packages'][0]['properties'],
                             {'Pkg.Revision': '2', 'AndroidVersion.ApiLevel': '35'})
            self.assertEqual(returned['packages'][1]['properties'], {'Pkg.Revision': '35.0.0'})
            self.assertEqual(set(returned['files']), {path[len(sdk) + 1:] for path, _ in expected_reads[1:]})
            self.assertTrue(clocks[0].finished)
            self.assertIsNone(helper.SDK_CURRENT_USE)
            with self.assertRaisesRegex(helper.Refused, '^provisioned-sdk-current-use-not-admitted$'):
                helper.admit_sdk_current_use(returned)

            failures = [
                ('missing-original', {receipt: FileNotFoundError('PRIVATE-SENTINEL')}),
                ('malformed-plist', {system: b'not a plist'}),
                ('duplicate-property', {platform_properties: b'Pkg.Revision=2\nPkg.Revision=2\nAndroidVersion.ApiLevel=35\n'}),
                ('invalid-utf8', {platform_properties: b'Pkg.Revision=2\nAndroidVersion.ApiLevel=\xff\n'}),
                ('wrong-revision', {platform_properties: b'Pkg.Revision=3\nAndroidVersion.ApiLevel=35\n'}),
                ('duplicate-receipt', {receipt: ((selected_id + '\n') * 2).encode()}),
                ('unselected-receipt', {receipt: b'0000000000000000000000000000000000000000\n'}),
                ('malformed-xml', {platform_xml: b'<repository>'}),
                ('xml-declaration', {platform_xml: b'<!DOCTYPE repository><repository />'}),
            ]
            for kind in ('package', 'license-definition', 'uses-license'):
                xml = helper.ET.fromstring(bodies[platform_xml])
                local = next(n for n in xml if n.tag.rsplit('}', 1)[-1] == 'localPackage')
                license_node = next(n for n in xml if n.tag.rsplit('}', 1)[-1] == 'license')
                if kind == 'package':
                    local.set('path', 'platforms;android-34')
                elif kind == 'license-definition':
                    license_node.text = 'wrong definition'
                else:
                    next(n for n in local if n.tag.rsplit('}', 1)[-1] == 'uses-license').set('ref', 'wrong-license')
                failures.append((kind, {platform_xml: helper.ET.tostring(xml, encoding='utf-8')}))
            for label, changes in failures:
                with self.subTest(refusal=label):
                    returned, failure, reads, publications, clocks = invoke(changes)
                    self.assertIsNone(returned)
                    self.assertIsInstance(failure, helper.Refused)
                    self.assertEqual(str(failure), 'sdk-observation-refused')
                    self.assertEqual(len(publications), 1)
                    report = publications[0]
                    self.assertEqual(report['status'], 'refused')
                    self.assertNotIn('originalsClosed', report)
                    self.assertNotIn('packages', report)
                    self.assertNotIn('PRIVATE-SENTINEL', json.dumps(report))
                    self.assertRegex(report['reason'], '^[a-z0-9-]{1,96}$')
                    self.assertTrue(clocks[0].failed)
                    self.assertFalse(clocks[0].finished)
            for fault in (KeyboardInterrupt('PRIVATE-SENTINEL'), SystemExit('PRIVATE-SENTINEL'),
                          helper.Refused('inert-deadline-expired')):
                with self.subTest(post_parse=type(fault).__name__):
                    returned, failure, reads, publications, clocks = invoke(late=fault)
                    self.assertIsNone(returned)
                    self.assertIsInstance(failure, helper.Refused)
                    self.assertEqual(str(failure), 'sdk-observation-refused')
                    self.assertEqual(reads, expected_reads)
                    self.assertEqual(len(publications), 1)
                    report = publications[0]
                    self.assertEqual(report['status'], 'refused')
                    for key in ('originalsClosed', 'packages', 'licenseDefinitionSha256',
                                'existingSelectedReceiptId', 'receiptIdCount', 'acceptancePerformed'):
                        self.assertNotIn(key, report)
                    self.assertNotIn('PRIVATE-SENTINEL', json.dumps(report))
                    self.assertTrue(clocks[0].failed)
                    self.assertFalse(clocks[0].finished)
            write_fault = OSError('PRIVATE-PUBLISH-SENTINEL')
            returned, failure, _, publications, _ = invoke(publication=write_fault)
            self.assertIsNone(returned)
            self.assertIs(failure, write_fault)
            self.assertEqual(publications, [])
        finally:
            helper.N, helper.P, helper.os, helper.read, helper.publish_json = original

    def test_read_rechecks_named_ancestors_and_closes_every_adopted_original(self):
        self.assertNotEqual(os.getuid(), 0, 'the genuine FD fixture is nonroot')
        helper = fixture_module('desktop/tools/macos_android_dependency_preparation.py', '_mrk_sdk_read_data')
        original_os = helper.os
        scratch = Path(os.environ['TMPDIR'])
        self.assertTrue(scratch.is_absolute())
        self.assertEqual(stat.S_IMODE(scratch.stat().st_mode), 0o700)
        raw = b'bounded synthetic metadata\n'
        cases = ('positive', 'bound', 'parent-open', 'short', 'trailing', 'held-post',
                 'named-post', 'ancestor-replaced', 'close', 'short-and-close')
        for kind in cases:
            with self.subTest(case=kind), tempfile.TemporaryDirectory(prefix='sdk-read-', dir=scratch) as temporary:
                root = Path(temporary)
                (root / 'a').mkdir(mode=0o700)
                (root / 'a/b').mkdir(mode=0o700)
                path = root / 'a/b/metadata.txt'
                path.write_bytes(raw)
                path.chmod(0o600)
                opened, attempts, consumed, rescued = [], [], set(), []
                file_fd = None
                file_stats = 0
                replaced = False
                close_fault = OSError('inert-consuming-close')
                open_fault = OSError('inert-parent-open')
                def tracked_open(name, flags, *args, **kwargs):
                    nonlocal file_fd
                    self.assertTrue(flags & os.O_NOFOLLOW)
                    self.assertTrue(flags & os.O_CLOEXEC)
                    if kind == 'parent-open' and len(opened) == 2:
                        raise open_fault
                    fd = os.open(name, flags, *args, **kwargs)
                    opened.append(fd)
                    if name == path.name:
                        self.assertTrue(flags & os.O_NONBLOCK)
                        file_fd = fd
                    else:
                        self.assertTrue(flags & os.O_DIRECTORY)
                    return fd
                def tracked_close(fd):
                    self.assertNotIn(fd, consumed)
                    attempts.append(fd)
                    os.close(fd)
                    consumed.add(fd)
                    if kind in ('close', 'short-and-close') and fd == file_fd:
                        raise close_fault
                def altered(state):
                    values = {name: getattr(state, name) for name in (
                        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                        'st_size', 'st_mtime_ns', 'st_ctime_ns')}
                    values['st_mtime_ns'] += 1
                    return types.SimpleNamespace(**values)
                def held_stat(fd):
                    nonlocal file_stats
                    value = os.fstat(fd)
                    if fd == file_fd:
                        file_stats += 1
                        if kind == 'held-post' and file_stats > 1:
                            return altered(value)
                    return value
                def named_stat(name, *args, **kwargs):
                    value = os.stat(name, *args, **kwargs)
                    return altered(value) if kind == 'named-post' and name == path.name else value
                def original_read(fd, size, offset):
                    nonlocal replaced
                    if kind in ('short', 'short-and-close') and offset == 0:
                        return os.pread(fd, max(size - 1, 0), offset)
                    if kind == 'trailing' and offset == len(raw):
                        return b'x'
                    if kind == 'ancestor-replaced' and not replaced:
                        # Old held leaf remains unchanged. Only the named ancestor
                        # now refers to a distinct directory, which must refuse.
                        replaced = True
                        (root / 'a').rename(root / 'retained-a')
                        (root / 'a').mkdir(mode=0o700)
                        (root / 'a/b').mkdir(mode=0o700)
                        (root / 'a/b/metadata.txt').write_bytes(raw)
                    return os.pread(fd, size, offset)
                helper.os = types.SimpleNamespace(**dict(vars(os), open=tracked_open, close=tracked_close,
                                                         fstat=held_stat, stat=named_stat, pread=original_read))
                returned, failure = None, None
                try:
                    try:
                        returned = helper.read(path, len(raw) - 1 if kind == 'bound' else len(raw))
                    except BaseException as error:
                        failure = error
                finally:
                    helper.os = original_os
                    # Explicit cleanup precedes every assertion; only this test's
                    # known originals are consumed, never a failed-close retry.
                    for fd in reversed(opened):
                        if fd not in consumed:
                            os.close(fd)
                            consumed.add(fd)
                            rescued.append(fd)
                self.assertEqual(rescued, [], 'product must attempt every adopted original once')
                self.assertEqual(len(attempts), len(set(attempts)))
                self.assertEqual(set(attempts), set(opened))
                if kind == 'positive':
                    self.assertIsNone(failure)
                    self.assertEqual(returned, (raw, helper.nine(path.stat())))
                else:
                    self.assertIsNone(returned)
                    if kind == 'parent-open':
                        self.assertIs(failure, open_fault)
                    else:
                        self.assertIsInstance(failure, helper.Refused)
                        expected = {'bound': 'original-file', 'short': 'original-short',
                                    'trailing': 'original-post', 'held-post': 'original-post',
                                    'named-post': 'original-post', 'ancestor-replaced': 'ancestor-original-post',
                                    'close': 'original-close-unknown', 'short-and-close': 'original-short'}[kind]
                        self.assertEqual(str(failure), expected)
        self.assertIs(helper.os, original_os)

    def test_verified_byte_loading_and_safe_early_diagnostics_keep_failure_closed(self):
        self.assertNotEqual(os.getuid(), 0)
        helper = fixture_module('desktop/tools/macos_android_dependency_preparation.py', '_mrk_sdk_load_data')
        scratch = Path(os.environ['TMPDIR'])
        self.assertEqual(stat.S_IMODE(scratch.stat().st_mode), 0o700)
        old_source, old_pins, old_read = helper.SOURCE, helper.PINS, helper.read
        name = '_mrk_sdk_authenticated_synthetic_module'
        self.assertNotIn(name, sys.modules)
        try:
            with tempfile.TemporaryDirectory(prefix='sdk-load-', dir=scratch) as temporary:
                source = Path(temporary)
                path = source / 'fixed.py'
                helper.SOURCE = source
                def body(raw):
                    path.write_bytes(raw)
                    path.chmod(0o600)
                    helper.PINS = {'fixed.py': [len(raw), hashlib.sha256(raw).hexdigest()]}
                body(b"TOKEN = 'authenticated-source'\n")
                loaded = helper.load(name, 'fixed.py')
                self.assertEqual(loaded.TOKEN, 'authenticated-source')
                self.assertIs(sys.modules[name], loaded)
                self.assertFalse((source / '__pycache__').exists())
                del sys.modules[name]
                for raw, exception in ((b"raise ValueError('fixed-loader-refusal')\n", ValueError),
                                       (b"raise KeyboardInterrupt('fixed-loader-interruption')\n", KeyboardInterrupt)):
                    body(raw)
                    with self.assertRaises(exception):
                        helper.load(name, 'fixed.py')
                    self.assertNotIn(name, sys.modules)
                    self.assertFalse((source / '__pycache__').exists())
                body(b"raise ValueError('authenticated-bytes')\n")
                changed = False
                def replace_after_authenticated_read(read_path, limit, **kwargs):
                    nonlocal changed
                    result = old_read(read_path, limit, **kwargs)
                    if read_path == path and not changed:
                        changed = True
                        path.write_bytes(b"raise LookupError('replacement-bytes')\n")
                    return result
                helper.read = replace_after_authenticated_read
                with self.assertRaisesRegex(ValueError, '^authenticated-bytes$'):
                    helper.load(name, 'fixed.py')
                self.assertTrue(changed)
                self.assertNotIn(name, sys.modules)
                self.assertFalse((source / '__pycache__').exists())
                helper.read = old_read
                body(b"TOKEN = 'post-replacement-must-refuse'\n")
                changed = False
                helper.read = replace_after_authenticated_read
                with self.assertRaisesRegex(helper.Refused, '^source-module-post$'):
                    helper.load(name, 'fixed.py')
                self.assertNotIn(name, sys.modules)
                helper.read = old_read
                body(b"TOKEN = 'collision-must-stay-original'\n")
                sentinel = object()
                sys.modules[name] = sentinel
                with self.assertRaisesRegex(helper.Refused, '^module-collision$'):
                    helper.load(name, 'fixed.py')
                self.assertIs(sys.modules[name], sentinel)
        finally:
            helper.SOURCE, helper.PINS, helper.read = old_source, old_pins, old_read
            sys.modules.pop(name, None)

        # Early main failure is exercised with real retained work descriptors and
        # real safe publisher, but a fixed inert Mac path/host adapter. No helper
        # import, vendor command or native host observation can occur here.
        expected_path = Path('/Users/runner/work/_temp/mrk-android-dependencies.Test0001')
        original = (helper.os, helper.sys, helper.admit_work, helper.context, helper.load,
                    helper.N, helper.P, helper.C)
        for kind in ('unsafe-name', 'unsafe-directory', 'wrong-scope', 'context', 'normal-load', 'transport-load'):
            with self.subTest(early=kind), tempfile.TemporaryDirectory(prefix='sdk-work-', dir=scratch) as temporary:
                directory = Path(temporary)
                if kind == 'unsafe-directory':
                    directory.chmod(0o777)
                admitted = []
                loads = []
                def admit(path):
                    self.assertEqual(path, expected_path)
                    private = original[2](directory)
                    admitted.append(private)
                    # Only the namespace string is DATA; original FD bindings and
                    # publication remain the real disposable /scratch directory.
                    return dict(private, path=expected_path)
                def context():
                    if kind == 'context':
                        raise helper.Refused('fixed-native-python-host')
                    return expected_path
                def load(module_name, relative):
                    loads.append((module_name, relative))
                    if kind == 'normal-load' or len(loads) == 2:
                        raise helper.Refused('source-module-pin')
                    return types.SimpleNamespace()
                environment = {'MRK_ANDROID_PREPARATION_WORK': '../unsafe' if kind == 'unsafe-name' else str(expected_path)}
                helper.os = types.SimpleNamespace(**dict(vars(os), environ=environment))
                helper.sys = types.SimpleNamespace(argv=['fixed-source', 'prepare-a' if kind == 'wrong-scope' else 'observe-sdk'])
                helper.admit_work, helper.context, helper.load = admit, context, load
                result = None
                try:
                    result = helper.main()
                finally:
                    helper.os, helper.sys, helper.admit_work, helper.context, helper.load, helper.N, helper.P, helper.C = original
                    directory.chmod(0o700)
                    # main must already have consumed these. This fallback closes
                    # only still-owned explicit originals before any assertions.
                    rescued = []
                    for private in admitted:
                        if private['fds']:
                            rescued.extend(private['fds'])
                            helper.close_chain(private['fds'], private['originals'])
                self.assertEqual(result, 78)
                self.assertEqual(rescued, [])
                leaves = sorted(p.name for p in directory.iterdir())
                if kind.startswith('unsafe-'):
                    self.assertEqual(leaves, [])
                    self.assertEqual(admitted, [])
                    self.assertEqual(loads, [])
                else:
                    self.assertEqual(leaves, ['observe-sdk-failure.json'])
                    path = directory / leaves[0]
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                    raw = path.read_bytes()
                    self.assertLessEqual(len(raw), 4096)
                    value = json.loads(raw)
                    self.assertEqual(set(value), {'status', 'stage', 'reason', 'scope',
                                                 'nativeOrTaskSuccess', 'cleanupAuthorized'})
                    self.assertEqual(value['status'], 'refused')
                    self.assertFalse(value['nativeOrTaskSuccess'])
                    self.assertFalse(value['cleanupAuthorized'])
                    self.assertEqual(value['scope'], 'observe-sdk')
                    self.assertEqual(value['stage'], {'wrong-scope': 'scope-context', 'context': 'scope-context',
                                                     'normal-load': 'normal-helper-load', 'transport-load': 'transport-helper-load'}[kind])
                    self.assertEqual(value['reason'], {'wrong-scope': 'fixed-source-scope', 'context': 'fixed-native-python-host',
                                                      'normal-load': 'source-module-pin', 'transport-load': 'source-module-pin'}[kind])
                    self.assertNotIn(str(directory), raw.decode())
