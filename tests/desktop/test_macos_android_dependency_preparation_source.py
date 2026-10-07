"""SOURCE plus inert SDK parser/loader and tiny nonroot original-FD regressions.

Never native SDK observation, vendor execution, licence acceptance or acquisition.
"""
import ast
import base64
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
                     and n.targets[0].id in ('ARCHIVES', 'PINS', 'RESOURCES', 'SDK_CURRENT_USE', 'RUN_SCOPE', 'SDK_METADATA')}
        self.assertEqual(constants['SDK_CURRENT_USE']['image'], {'ImageOS': 'macos26', 'ImageVersion': '20260907.0351.1'})
        self.assertEqual(constants['SDK_CURRENT_USE']['productVersion'], '26.6.2')
        self.assertEqual(len(constants['SDK_CURRENT_USE']['files']), 5)
        self.assertEqual(constants['RUN_SCOPE'], 'prepare-a')
        for entry in constants['SDK_METADATA']:
            raw = (ROOT / entry['path']).read_bytes()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (entry['bytes'], entry['sha256']))
        self.assertEqual([r['role'] for r in constants['ARCHIVES']], ['jdk', 'sdk-platform', 'sdk-build-tools', 'gradle', 'aapt2'])
        self.assertEqual(sum(r['bytes'] for r in constants['ARCHIVES']), 469391018)
        for path, pin in constants['RESOURCES'].items():
            raw = (ROOT / path).read_bytes()
            self.assertEqual([len(raw), hashlib.sha256(raw).hexdigest()], pin)
        project = json.loads((ROOT / 'desktop/tools/android_dependency_preparation_data/project-v1.json').read_bytes())
        bodies = {name: base64.b64decode(raw, validate=True) for name, raw in project['files'].items()}
        self.assertEqual(len(bodies), 9)
        build = bodies['project/build.gradle'].decode()
        self.assertIn('resolutionStrategy.activateDependencyLocking()', build)
        self.assertIn('lockAllConfigurations()', build)
        self.assertIn('lockMode = LockMode.STRICT', build)
        self.assertIn("classpath 'com.android.tools.build:gradle:8.9.2'", build)
        import xml.etree.ElementTree as ET
        manifest = ET.fromstring(bodies['project/app/src/main/AndroidManifest.xml'])
        application = manifest.find('application')
        self.assertIsNotNone(application)
        self.assertNotIn('{http://schemas.android.com/apk/res/android}debuggable', application.attrib)
        release_build = bodies['project/app/build.gradle'].decode()
        self.assertIn('debuggable false', release_build)
        for suppression in ('lintOptions', 'lint {', 'abortOnError', 'checkReleaseBuilds', 'disable', 'baseline'):
            self.assertNotIn(suppression, release_build)
        self.assertNotIn('tools:ignore', bodies['project/app/src/main/AndroidManifest.xml'].decode())
        for incompatible in ('failOnDynamicVersions', 'failOnChangingVersions', 'failOnNonReproducibleResolution'):
            self.assertNotIn(incompatible, build)
        self.assertIn('dependencyVerificationMode = DependencyVerificationMode.STRICT', bodies['project/settings.gradle'].decode())
        self.assertIn('<verify-metadata>true</verify-metadata>',
                      (ROOT / 'desktop/tools/android_dependency_preparation_data/verification-v1.xml').read_text())
        total = sum(map(len, bodies.values()))
        self.assertEqual(total, 3962)
        materializer = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'materialize')
        bound = next(n for n in ast.walk(materializer) if isinstance(n, ast.Call) and len(n.args) == 2
                     and isinstance(n.args[1], ast.Constant) and n.args[1].value == 'fixture-decoded-bound')
        self.assertEqual(ast.literal_eval(bound.args[0].comparators[0]), total)
        self.assertIn("'pythonExecutable': python_executable", source)
        self.assertIn("value['pythonExecutable'] == observed_python_executable()", source)
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
        self.assertIn('timeout-minutes: 53', workflow)
        self.assertIn('2+3+3+1+37+2+2=50', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('python-version: \'3.14.7\'', workflow)
        self.assertNotIn("macos_android_dependency_preparation.py observe-sdk", workflow)
        self.assertIn("macos_android_dependency_preparation.py prepare-a", workflow)
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
            self.assertEqual(helper.SDK_CURRENT_USE['productVersion'], '26.6.2')
            with self.assertRaisesRegex(helper.Refused, '^provisioned-sdk-source-nomination-mismatch$'):
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
                helper.sys = types.SimpleNamespace(argv=['fixed-source', 'observe-sdk' if kind == 'wrong-scope' else 'prepare-a'])
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
                    self.assertEqual(leaves, ['prepare-a-failure.json'])
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
                    self.assertEqual(value['scope'], 'prepare-a')
                    self.assertEqual(value['stage'], {'wrong-scope': 'scope-context', 'context': 'scope-context',
                                                     'normal-load': 'normal-helper-load', 'transport-load': 'transport-helper-load'}[kind])
                    self.assertEqual(value['reason'], {'wrong-scope': 'fixed-source-scope', 'context': 'fixed-native-python-host',
                                                      'normal-load': 'source-module-pin', 'transport-load': 'source-module-pin'}[kind])
                    self.assertNotIn(str(directory), raw.decode())

    def test_a_owned_startup_named_digest_and_exact_source_metadata_projection(self):
        self.assertNotEqual(os.getuid(), 0)
        helper = fixture_module('desktop/tools/macos_android_dependency_preparation.py', '_mrk_a_files_data')
        transport = fixture_module('desktop/tools/macos_android_supplier_preparation.py', '_mrk_a_paths_data')
        scratch = Path(os.environ['TMPDIR'])
        class Clock:
            def __init__(self, seconds=810): self.failed = False
            def check(self): return 1
        with tempfile.TemporaryDirectory(prefix='a-files-', dir=scratch) as temporary:
            work = Path(temporary)
            adopted = []
            original_admit = helper.admit_work
            def admit(path):
                private = original_admit(path); adopted.append(private); return private
            fault = KeyboardInterrupt('inert-startup')
            def fail_clock(seconds): raise fault
            helper.admit_work = admit; helper.N = types.SimpleNamespace(PhaseClock=fail_clock)
            with self.assertRaises(KeyboardInterrupt) as caught:
                helper.observe_sdk_current_use(work)
            self.assertIs(caught.exception, fault)
            self.assertEqual(len(adopted), 1)
            self.assertEqual(adopted[0]['fds'], [])
            helper.admit_work = original_admit
            helper.N = types.SimpleNamespace(PhaseClock=Clock); helper.P = transport; helper.SOURCE = ROOT
            (work / 'tools').mkdir(mode=0o700)
            a = helper.Acquisition(work)
            # Only the two committed tiny XMLs are projected; no archive/vendor command.
            a.project_sdk_metadata()
            self.assertEqual(a.files, 2); self.assertEqual(a.writes, 35551)
            self.assertEqual(a.reads, 2 * 35551 + 4)
            self.assertLessEqual(a.roster_bytes, 4 << 20)
            self.assertLessEqual(a.directory_bytes, 4 << 20)
            for entry, row in zip(helper.SDK_METADATA, a.roster):
                path = work / 'tools' / entry['target']
                self.assertEqual(path.read_bytes(), (ROOT / entry['path']).read_bytes())
                self.assertEqual(row['origin'], entry['origin'])
                self.assertEqual(row['sourcePath'], entry['path'])
                self.assertNotIn('vendorMode', row)
                self.assertEqual(row['mode'], 0o444)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)  # Not sealed/executable yet.
            self.assertFalse((work / 'tools/sdk/licenses').exists())
            # Tiny inert observer member: EOF is charged; primary digest refusal
            # survives a consuming leaf-close fault, while every parent closes.
            opens, closes = [], []
            original_os = helper.os
            def tracked_open(*args, **kwargs):
                fd = os.open(*args, **kwargs); opens.append(fd); return fd
            def tracked_close(fd):
                closes.append(fd); os.close(fd)
                if fd == opens[-1]: raise OSError('inert-consuming-leaf-close')
            helper.os = types.SimpleNamespace(**dict(vars(os), open=tracked_open, close=tracked_close))
            tiny = helper.Acquisition(work); tiny.role = {'role': 'gradle', 'archivePrefix': 'fixed'}
            row = ('fixed/observer-fixture', 'file', 0o100644, 3, '0' * 64)
            rescued = []
            try:
                tiny.begin(row); tiny.block(row[0], 0, b'abc')
                with self.assertRaisesRegex(helper.Refused, '^tool-payload-digest$'): tiny.end(row)
            finally:
                helper.os = original_os
                for fd in opens:
                    if fd not in closes: os.close(fd); rescued.append(fd)
            self.assertEqual(rescued, []); self.assertEqual(len(closes), len(set(closes)))
            self.assertIsNone(tiny.active)
            good = ('fixed/observer-eof', 'file', 0o100644, 3, helper.digest(b'abc'))
            tiny.begin(good); tiny.block(good[0], 0, b'abc'); tiny.end(good)
            self.assertEqual(tiny.reads, 4)
            # Renaming an ancestor leaves the held leaf intact but must revoke digest.
            (work / 'a').mkdir(mode=0o700)
            path = work / 'a/file'; path.write_bytes(b'bounded'); path.chmod(0o600)
            original_os = helper.os; changed = False
            def pread(fd, size, offset):
                nonlocal changed
                data = os.pread(fd, size, offset)
                if not changed:
                    changed = True; (work / 'a').rename(work / 'retained-a'); (work / 'a').mkdir(mode=0o700)
                    (work / 'a/file').write_bytes(b'bounded')
                return data
            helper.os = types.SimpleNamespace(**dict(vars(os), pread=pread))
            try:
                with self.assertRaisesRegex(helper.Refused, '^ancestor-original-post$'):
                    helper.file_digest(path, 7, Clock())
            finally: helper.os = original_os
            self.assertTrue(changed)
            with self.assertRaisesRegex(helper.Refused, '^preparation-output-bound$'):
                helper.publish_preparation(work, '../outside', b'x')

    def test_a_transport_consuming_closes_and_final_caller_deadline(self):
        self.assertNotEqual(os.getuid(), 0)
        helper = fixture_module('desktop/tools/macos_android_dependency_preparation.py', '_mrk_a_transport_data')
        scratch = Path(os.environ['TMPDIR'])
        class Clock:
            def __init__(self, seconds):
                self.deadline = helper.time.monotonic_ns() + seconds * 1000000000
            def check(self): return helper.time.monotonic_ns()
        helper.N = types.SimpleNamespace(PhaseClock=Clock)
        for kind in ('redirect-close', 'read-and-close'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix='a-transport-', dir=scratch) as temporary:
                work = Path(temporary); (work / 'archives').mkdir(mode=0o700)
                opens, closes, requested = [], [], []
                primary = ValueError('inert-first-failure')
                close_fault = RuntimeError('inert-consuming-close')
                class Response:
                    code = 302 if kind == 'redirect-close' else 200
                    count = 0
                    def read(self, amount): raise primary
                    def close(self):
                        self.count += 1
                        raise primary if kind == 'redirect-close' else close_fault
                response = Response()
                class Opener:
                    def open(self, req, timeout): requested.append(req.full_url); return response
                helper.P = types.SimpleNamespace(response_headers=lambda r: {'location': 'https://fixed.invalid/body'} if r.code == 302 else {},
                    release_redirect=lambda value: value)
                original_os = helper.os
                def tracked_open(*args, **kwargs):
                    fd = os.open(*args, **kwargs); opens.append(fd); return fd
                def tracked_close(fd): closes.append(fd); os.close(fd)
                helper.os = types.SimpleNamespace(**dict(vars(os), open=tracked_open, close=tracked_close))
                rescued = []
                try:
                    a = helper.Acquisition(work)
                    role = {'role': 'fixed', 'url': 'https://github.com/fixed' if kind == 'redirect-close' else 'https://fixed.invalid/body',
                            'bytes': 1, 'sha256': '0' * 64}
                    with self.assertRaises(ValueError) as caught: a.capture(role, Opener())
                    self.assertIs(caught.exception, primary)
                finally:
                    helper.os = original_os
                    for fd in opens:
                        if fd not in closes: os.close(fd); rescued.append(fd)
                self.assertEqual(rescued, [])
                self.assertEqual(len(closes), len(set(closes)))
                self.assertEqual(set(closes), set(opens))
                self.assertEqual(response.count, 1)
                self.assertEqual(len(requested), 1)
        with tempfile.TemporaryDirectory(prefix='a-publish-', dir=scratch) as temporary:
            work = Path(temporary); events = []; original_os = helper.os
            def closed(fd): os.close(fd); events.append('close')
            class LatePublication:
                count = 0
                def check(self):
                    self.count += 1
                    if self.count == 4:
                        self_outer.assertTrue(events)
                        raise helper.Refused('inert-publication-deadline')
            self_outer = self
            helper.os = types.SimpleNamespace(**dict(vars(os), close=closed))
            try:
                with self.assertRaisesRegex(helper.Refused, '^inert-publication-deadline$'):
                    helper.publish_preparation(work, 'acquisition.json', b'{}', clock=LatePublication())
            finally: helper.os = original_os
            self.assertEqual((work / 'acquisition.json').read_bytes(), b'{}')
        # main must consume its real private chain before the final clock call;
        # a late failure cannot return wrapper0. No prepare/vendor body executes.
        expected = Path('/Users/runner/work/_temp/mrk-android-dependencies.Test0001')
        for late in (False, True):
            with self.subTest(late=late), tempfile.TemporaryDirectory(prefix='a-final-', dir=scratch) as temporary:
                work = Path(temporary); adopted = []; finished = []
                original = helper.admit_work, helper.os, helper.sys, helper.context, helper.load, helper.prepare
                def admit(path):
                    private = original[0](work); adopted.append(private); return dict(private, path=expected)
                class FinalClock:
                    def finish(self):
                        self_outer.assertEqual(adopted[0]['fds'], [])
                        finished.append(True)
                        if late: raise KeyboardInterrupt('inert-late-finality')
                self_outer = self
                helper.admit_work = admit
                helper.os = types.SimpleNamespace(**dict(vars(os), environ={'MRK_ANDROID_PREPARATION_WORK': str(expected)}))
                helper.sys = types.SimpleNamespace(argv=['fixed', 'prepare-a'])
                helper.context = lambda: expected; helper.load = lambda *args: types.SimpleNamespace()
                helper.prepare = lambda work, private: FinalClock()
                try: result = helper.main()
                finally:
                    helper.admit_work, helper.os, helper.sys, helper.context, helper.load, helper.prepare = original
                    for private in adopted:
                        if private['fds']: helper.close_chain(private['fds'], private['originals'])
                self.assertEqual(result, 78 if late else 0)
                self.assertEqual(finished, [True])

    def test_a_actual_report_and_complete_cleanup_receipt_reject_partial_evidence(self):
        self.assertNotEqual(os.getuid(), 0)
        helper = fixture_module('desktop/tools/macos_android_dependency_preparation.py', '_mrk_a_receipt_data')
        normal = fixture_module('desktop/tools/macos_normal_ui_runner.py', '_mrk_a_record_data')
        helper.N = normal
        scratch = Path(os.environ['TMPDIR']); sha = 'c' * 40
        helper.os = types.SimpleNamespace(**dict(vars(os), environ={'GITHUB_SHA': sha}))
        class Clock:
            def check(self): return 1
        # Real tiny project materialization catches stale decoded-total guards;
        # only path syntax is adapted, and no Gradle/vendor code executes.
        helper.P = types.SimpleNamespace(relative=lambda name: self.assertTrue(
            name and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/'))))
        project_raw = (ROOT / 'desktop/tools/android_dependency_preparation_data/project-v1.json').read_bytes()
        verification = (ROOT / 'desktop/tools/android_dependency_preparation_data/verification-v1.xml').read_bytes()
        with tempfile.TemporaryDirectory(prefix='a-fixture-', dir=scratch) as temporary:
            work = Path(temporary)
            originals = helper.materialize(work, project_raw, verification, Clock())
            decoded = {name.removeprefix('project/'): base64.b64decode(raw, validate=True)
                       for name, raw in json.loads(project_raw)['files'].items()}
            self.assertEqual(sum(map(len, decoded.values())), 3962)
            decoded['gradle/verification-metadata.xml'] = verification
            self.assertEqual(originals, {name: helper.digest(raw) for name, raw in decoded.items()})
            self.assertEqual({name: (work / 'run/project' / name).read_bytes() for name in decoded}, decoded)
        with tempfile.TemporaryDirectory(prefix='a-receipt-', dir=scratch) as temporary:
            work = Path(temporary)
            # Explicit inert validator DATA, never a native-observation receipt.
            report = dict(helper.SDK_CURRENT_USE, source=sha, status='observed-not-admitted', originalsClosed=True,
                classification='current-run-provisioned-sdk-observation-not-license-entitlement', acceptancePerformed=False)
            path = work / 'sdk-observation.json'
            def write_report(value): path.write_bytes(helper.encoded(value)); path.chmod(0o600)
            write_report(report)
            self.assertEqual(helper.current_observation(work, Clock()), helper.digest(path.read_bytes()))
            for change in ({'source': 'd' * 40}, {'originalsClosed': False}, {'status': 'refused'},
                           {'acceptancePerformed': True}, {'productVersion': '26.0.1'}):
                write_report(dict(report, **change))
                with self.assertRaises(helper.Refused): helper.current_observation(work, Clock())
            def record_clock(seconds):
                return {'startNs': '0', 'deadlineNs': str(seconds * 1000000000), 'beforePublicationNs': '1',
                        'postCloseDeadlineRequired': True}
            # These are explicitly inert reader DATA, not claimed native facts.
            # Exercise the real acquisition reader before later cleanup adapters.
            write_report(report)
            for name, raw in (('tool-roster.json', b'[]'), ('directory-roster.json', b'{}')):
                (work / name).write_bytes(raw); (work / name).chmod(0o600)
            acquisition = {'status': 'closed', 'source': sha, 'workflow': helper.WORKFLOW, 'ref': helper.REF,
                'phase': 'acquisition', 'archives': helper.ARCHIVES, 'archiveBytes': 469391018,
                'toolBytes': 1, 'readBytes': 1, 'files': 1, 'entries': 1, 'stockCaSha256': '0' * 64,
                'nativeExecuted': False, 'protectedRegistration': False,
                'sdkObservationSha256': helper.digest(path.read_bytes()), 'sdkMetadata': helper.SDK_METADATA,
                'toolRosterSha256': helper.digest(b'[]{}'), 'pythonExecutable': sys.executable,
                'phaseClock': record_clock(810)}
            receipt_path = work / 'acquisition.json'
            def write_acquisition(value):
                receipt_path.write_bytes(helper.encoded(value)); receipt_path.chmod(0o600)
            write_acquisition(acquisition)
            self.assertEqual(helper.observed_python_executable(), sys.executable)
            admitted, receipt_sha = helper.acquisition_receipt(work, Clock())
            self.assertEqual(admitted, acquisition)
            self.assertEqual(receipt_sha, helper.digest(receipt_path.read_bytes()))
            malformed_paths = [None, 1, '', 'relative/python', '/tmp//python', '/tmp/./python',
                '/tmp/../python', '/tmp/python\n', '/tmp/python\x00', '/tmp/python\x7f', '/tmp/pýthon', '/' + 'p' * 1024]
            for invalid in malformed_paths + ['/different/actual/python']:
                write_acquisition(dict(acquisition, pythonExecutable=invalid))
                with self.subTest(python=repr(invalid)), self.assertRaisesRegex(helper.Refused, '^acquisition-python-binding$'):
                    helper.acquisition_receipt(work, Clock())
            for invalid in (dict(acquisition, extra=True), {k: v for k, v in acquisition.items() if k != 'pythonExecutable'}):
                write_acquisition(invalid)
                with self.assertRaisesRegex(helper.Refused, '^acquisition-fields$'):
                    helper.acquisition_receipt(work, Clock())
            saved_sys = helper.sys
            try:
                for invalid in malformed_paths:
                    helper.sys = types.SimpleNamespace(executable=invalid)
                    with self.assertRaisesRegex(helper.Refused, '^python-executable-path$'):
                        helper.observed_python_executable()
            finally: helper.sys = saved_sys
            write_acquisition(acquisition)
            _, task, jdk = helper.arguments(work)
            head = ['/usr/bin/git', '-C', str(helper.SOURCE), 'rev-parse', 'HEAD']
            clean = ['/usr/bin/git', '-C', str(helper.SOURCE), 'status', '--porcelain=v1', '--untracked-files=all']
            commands = [('source-head-pre', head, 10, 4096), ('source-clean-pre', clean, 10, 16384),
                ('android-public-tool-acquisition', [sys.executable, '-I', '-S', '-B',
                    str(helper.SOURCE / 'desktop/tools/macos_android_dependency_preparation.py'), 'acquire'], 840, 16384),
                ('android-dependency-jdk-version', [str(jdk / 'bin/java'), '-version'], 15, 8192),
                ('android-dependency-gradle-version', ['/bin/sh', str(work / 'tools/gradle/bin/gradle'), '--version'], 15, 8192),
                ('android-dependency-lock-task', task, 900, 2 << 20),
                ('source-head-post', head, 10, 4096), ('source-clean-post', clean, 10, 16384)]
            records = []
            for role, argv, cap, limit in commands:
                body = (sha + '\n').encode() if role.startswith('source-head') else b''
                records.append({'role': role, 'returncode': 0, 'timeoutSeconds': cap, 'roleCapSeconds': cap,
                    'outputLimitBytes': limit, 'argvSha256': helper.digest(normal.encoded(argv)), 'stdoutBytes': len(body),
                    'stdoutSha256': helper.digest(body), 'stderrBytes': 0, 'stderrSha256': helper.digest(b'')})
            identity = list(helper.nine(work.stat())[:5])
            value = {'schemaVersion': 1, 'phase': 'A', 'status': 'closed-awaiting-distinct-data-review',
                'source': sha, 'workflow': helper.WORKFLOW, 'ref': helper.REF, 'wrapperReturncodeRequired': 0,
                'commands': records, 'sourcePrePost': True, 'toolRosterSha256': '1' * 64,
                'acquisitionSha256': '2' * 64, 'acquisitionClock': record_clock(900), 'sdkObservationSha256': '3' * 64,
                'sdkMetadata': helper.SDK_METADATA, 'aab': {'bytes': 4, 'sha256': '4' * 64},
                'fixtureSha256': helper.digest(b'project'), 'verificationSha256': helper.digest(b'verification'),
                'workIdentity': identity, 'disposalIdentities': {k: identity for k in ('archives', 'tools', 'run')},
                'protectedRegistration': False, 'uiQualification': False, 'phaseClock': record_clock(1200)}
            helper.acquisition_receipt = lambda work, clock: ({'sdkObservationSha256': '3' * 64, 'toolRosterSha256': '1' * 64}, '2' * 64)
            helper.resources = lambda: (b'project', b'verification')
            helper.read = lambda path, limit, clock: ((ROOT / path.relative_to(helper.SOURCE)).read_bytes(), None)
            helper.cleanup_receipt(work, value, Clock())
            mutations = [('phase', 'B'), ('workflow', 'wrong'), ('source', 'e' * 40), ('wrapperReturncodeRequired', False),
                         ('toolRosterSha256', '9' * 64), ('fixtureSha256', '9' * 64), ('commands', records[:-1])]
            for key, invalid in mutations:
                with self.subTest(field=key), self.assertRaises(helper.Refused):
                    helper.cleanup_receipt(work, dict(value, **{key: invalid}), Clock())
            for key, invalid in (('argvSha256', 'f' * 64), ('roleCapSeconds', 901), ('timeoutSeconds', 0),
                                 ('returncode', False), ('stdoutBytes', (2 << 20) + 1)):
                modified = json.loads(json.dumps(value)); modified['commands'][5][key] = invalid
                with self.subTest(record=key), self.assertRaises(helper.Refused): helper.cleanup_receipt(work, modified, Clock())
            for change in ({'deadlineNs': '1'}, {'beforePublicationNs': str(1200 * 1000000000)},
                           {'postCloseDeadlineRequired': False}):
                modified = dict(value, phaseClock=dict(value['phaseClock'], **change))
                with self.subTest(clock=change), self.assertRaises(helper.Refused): helper.cleanup_receipt(work, modified, Clock())

        # Inert prepare-path adapters prove that the admitted acquisition roster
        # must equal the first live tool POST BEFORE any Java/Gradle entry. These
        # synthetic return values are control-flow DATA, never native receipts.
        flow = fixture_module('desktop/tools/macos_android_dependency_preparation.py', '_mrk_a_roster_flow_data')
        class FlowClock:
            def __init__(self, seconds): self.seconds = seconds
            def before_publication(self): return {'inertSeconds': self.seconds}
            def finish(self): pass
        flow.os = types.SimpleNamespace(**dict(vars(os), statvfs=lambda path: types.SimpleNamespace(f_bavail=8 << 30, f_frsize=1),
            environ={k: 'inert' for k in ('GITHUB_REPOSITORY', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'GITHUB_SHA',
                'GITHUB_WORKFLOW_SHA', 'GITHUB_WORKFLOW_REF', 'GITHUB_WORKSPACE', 'RUNNER_ENVIRONMENT',
                'RUNNER_OS', 'RUNNER_ARCH', 'MRK_ANDROID_PREPARATION_WORK')}))
        flow.observe_sdk_current_use = lambda work, private: object()
        flow.admit_sdk_current_use = lambda value: None
        flow.resources = lambda: (b'project', b'verification')
        flow.source_original = lambda phase, suffix: None
        flow.publish_preparation = lambda *args, **kwargs: None
        flow.acquisition_receipt = lambda work, clock: ({'toolRosterSha256': '1' * 64}, '2' * 64)
        flow.materialize = lambda *args: {}
        reached = ValueError('inert-first-vendor-entry')
        for mismatch in (True, False, None):
            with self.subTest(live_roster_mismatch=mismatch), tempfile.TemporaryDirectory(prefix='a-roster-flow-', dir=scratch) as temporary:
                calls = []
                class Phase:
                    def __init__(self, *args): self.records = []
                    def call(self, role, *args):
                        calls.append(role)
                        if mismatch is None:
                            return types.SimpleNamespace(returncode=1 if role == 'android-dependency-lock-task' else 0, stderr=b'inert')
                        if role != 'android-public-tool-acquisition': raise reached
                        return types.SimpleNamespace(returncode=0)
                flow.N = types.SimpleNamespace(PhaseClock=FlowClock, NormalPhase=Phase, load_normal_owner=lambda source: object())
                flow.tool_post = lambda work, clock: ('3' if mismatch else '1') * 64
                def diagnostic_fault(*args): raise KeyboardInterrupt('inert-diagnostic-failure')
                flow.publish_gradle_failure = diagnostic_fault
                if mismatch is None:
                    with self.assertRaisesRegex(flow.Refused, '^gradle-original-return$'):
                        flow.prepare(Path(temporary), private=object())
                    self.assertEqual(calls, ['android-public-tool-acquisition', 'android-dependency-jdk-version',
                                            'android-dependency-gradle-version', 'android-dependency-lock-task'])
                elif mismatch:
                    with self.assertRaisesRegex(flow.Refused, '^acquisition-live-tool-roster$'):
                        flow.prepare(Path(temporary), private=object())
                    self.assertEqual(calls, ['android-public-tool-acquisition'])
                else:
                    with self.assertRaises(ValueError) as caught: flow.prepare(Path(temporary), private=object())
                    self.assertIs(caught.exception, reached)
                    self.assertEqual(calls, ['android-public-tool-acquisition', 'android-dependency-jdk-version'])

        # One bounded realistic failure projection: nested public causes and
        # SOURCE-derived locations/API/modules, never raw stderr or private text.
        project_raw = (ROOT / 'desktop/tools/android_dependency_preparation_data/project-v1.json').read_bytes()
        verification = (ROOT / 'desktop/tools/android_dependency_preparation_data/verification-v1.xml').read_bytes()
        work = Path('/case/PRIVATE-WORK-SENTINEL')
        stderr = ("FAILURE: Build failed with an exception.\n* Where:\n"
            "Build file '" + str(work / 'run/project/build.gradle') + "' line: 21\n"
            "* What went wrong:\nA problem occurred evaluating root project 'PRIVATE-NAME-SENTINEL'.\n"
            "> Could not find method dependencyLocking() for arguments [PRIVATE-ARG-SENTINEL].\n"
            "> Could not resolve com.android.tools.build:gradle:8.9.2.\n"
            "> Could not resolve com.private.secret:INTERNAL-MODULE:9.0.0.\n"
            "* Exception is:\norg.gradle.api.GradleScriptException: PRIVATE-MESSAGE-SENTINEL\n"
            "Caused by: org.codehaus.groovy.control.MultipleCompilationErrorsException: startup failed:\n"
            "unable to resolve class org.gradle.api.artifacts.dsl.LockMode\n"
            "Caused by: javax.net.ssl.SSLHandshakeException: PKIX path building failed\n"
            "Could not GET 'https://dl.google.com/PRIVATE-URL-SENTINEL?token=PRIVATE-TOKEN-SENTINEL'.\n"
            "Received status code 403 from server: PRIVATE-HEADER-SENTINEL\n"
            "Caused by: com.private.SecretException: PRIVATE-CAUSE-SENTINEL\n").encode()
        value = helper.gradle_failure_projection(stderr, work, project_raw, verification)
        self.assertEqual(value['stderrBytes'], len(stderr)); self.assertEqual(value['stderrSha256'], helper.digest(stderr))
        self.assertEqual(value['sections'], ['where', 'what-went-wrong', 'exception'])
        self.assertEqual([r['class'] for r in value['causes']], ['org.gradle.api.GradleScriptException',
            'org.codehaus.groovy.control.MultipleCompilationErrorsException', 'javax.net.ssl.SSLHandshakeException'])
        self.assertEqual([r['index'] for r in value['causes']], [1, 2, 3])
        self.assertEqual(value['scan']['unknownCauses'], 1)
        self.assertTrue({'script-evaluation-failed', 'api-method-resolution-failed', 'script-startup-failed',
                         'api-class-resolution-failed', 'tls-certification-path-failed', 'http-403'} <= set(value['facts']))
        self.assertEqual(value['modules'], [{'coordinate': 'com.android.tools.build:gradle:8.9.2', 'fact': 'could-not-resolve'}])
        self.assertIn('dependencyLocking', value['symbols'])
        self.assertIn('org.gradle.api.artifacts.dsl.LockMode', value['symbols'])
        self.assertEqual(value['repositories'], ['google-maven'])
        self.assertEqual([(r['file'], r['line']) for r in value['locations']], [('project/build.gradle', 21)])
        source = base64.b64decode(json.loads(project_raw)['files']['project/build.gradle']).decode().splitlines()
        self.assertEqual(value['locations'][0]['sourceLine'], source[20])
        public = helper.encoded(value).decode()
        self.assertLessEqual(len(public.encode()), 12 << 10)
        for private in ('PRIVATE-', str(work), 'com.private', 'INTERNAL-MODULE', 'https://', 'token='):
            self.assertNotIn(private, public)
        # Both original streams, previously omitted RuntimeException and direct
        # public-source frames; no exception message or private task/path escapes.
        stderr_context = ("* What went wrong:\nExecution failed for task ':app:processReleaseResources'.\n"
            "* Exception is:\norg.gradle.api.tasks.TaskExecutionException: PRIVATE-OUTER\n"
            "\tat org.gradle.api.tasks.TaskExecutionException.report(TaskExecutionException.java:41)\n"
            "Caused by: java.lang.RuntimeException: PRIVATE-INNER\n"
            "\tat com.android.build.gradle.internal.tasks.ResourceTask.run(ResourceTask.kt:73)\n"
            "\tat com.android.build.gradle.internal.tasks.ResourceTask.invoke(ResourceTask.kt:74)\n"
            "\tat com.android.build.gradle.internal.tasks.ResourceTask.extra(ResourceTask.kt:75)\n"
            "Caused by: org.gradleSecret.PRIVATEError: PRIVATE-NAMESPACE\n"
            "\tat com.private.Secret.call(/PRIVATE/PATH/File.java:7)\n"
            "Execution failed for task ':private:PRIVATE_TASK'.\n").encode()
        stdout_context = ("> Task :app:processReleaseResources FAILED\n"
            "> Task :private:PRIVATE_TASK FAILED\n"
            "> Task :app:PRIVATE/TASK FAILED\n"
            "Read-only file system: /PRIVATE/PATH\n").encode()
        context = helper.gradle_failure_projection(stderr_context, work, project_raw, verification, stdout=stdout_context)
        self.assertEqual((context['stdoutBytes'], context['stdoutSha256']), (len(stdout_context), helper.digest(stdout_context)))
        self.assertEqual(context['scan']['streamLines']['stderr'] + context['scan']['streamLines']['stdout'], context['scan']['lines'])
        self.assertEqual([r['class'] for r in context['causes']],
                         ['org.gradle.api.tasks.TaskExecutionException', 'java.lang.RuntimeException'])
        self.assertEqual(context['scan']['unknownCauses'], 1)
        self.assertEqual([(r['task'], r['stream']) for r in context['tasks']],
                         [(':app:processReleaseResources', 'stderr'), (':app:processReleaseResources', 'stdout')])
        self.assertEqual([(r['causeIndex'], r['file'], r['line']) for r in context['frames']],
                         [(1, 'TaskExecutionException.java', 41), (2, 'ResourceTask.kt', 73), (2, 'ResourceTask.kt', 74)])
        self.assertIn('filesystem-read-only', context['facts'])
        self.assertNotIn('PRIVATE', helper.encoded(context).decode())
        issue = helper.gradle_failure_projection(b'', work, project_raw, verification,
            stdout=b'Error: PRIVATE-MESSAGE [HardcodedDebugMode]\n')
        self.assertIn('HardcodedDebugMode', issue['symbols'])
        self.assertNotIn('PRIVATE', helper.encoded(issue).decode())
        stdout_only = helper.gradle_failure_projection(b'', work, project_raw, verification, stdout=stdout_context)
        self.assertEqual(stdout_only['tasks'][0]['stream'], 'stdout')
        self.assertIn('filesystem-read-only', stdout_only['facts'])
        shared = helper.gradle_failure_projection(b'x\n' * 4095, work, project_raw, verification,
                                                  stdout=b'> Task :app:bundleRelease FAILED\nignored\n')
        self.assertEqual(shared['scan']['lines'], 4096); self.assertTrue(shared['scan']['inputTruncated'])
        self.assertEqual(shared['scan']['streamLines'], {'stderr': 4095, 'stdout': 1})
        self.assertEqual(shared['tasks'][0]['task'], ':app:bundleRelease')
        helper.gradle_failure_projection(b'x' * (1 << 20), work, project_raw, verification, stdout=b'y' * (1 << 20))
        with self.assertRaisesRegex(helper.Refused, '^gradle-diagnostic-input-bound$'):
            helper.gradle_failure_projection(b'x' * (1 << 20), work, project_raw, verification, stdout=b'y' * ((1 << 20) + 1))
        for public in ('org.gradle', 'com.android', 'java', 'javax', 'groovy', 'org.codehaus.groovy'):
            diagnostic = ('Caused by: ' + public + '.SomeException: PRIVATE\n'
                '\tat ' + public + '.SomeClass.run(SomeClass.java:17)\n').encode()
            admitted = helper.gradle_failure_projection(diagnostic, work, project_raw, verification)
            self.assertEqual(admitted['causes'][0]['class'], public + '.SomeException')
            self.assertEqual(admitted['frames'][0]['file'], 'SomeClass.java')
        for invalid in ('org.gradleSecret.Hidden', 'com.androidPrivate.Hidden', 'private.Secret',
                        'java..Hidden', 'java.' + 'x' * 65, 'org.gradle.' + 'x' * 221):
            refused = helper.gradle_failure_projection(('Caused by: ' + invalid + ': PRIVATE\n').encode(), work, project_raw, verification)
            self.assertEqual(refused['causes'], [])
        for frame in ('at java.lang.Test.call(/private/Secret.java:1)', 'at java.lang.Test.call(Secret.java:0)',
                      'at java.lang.Test.call(Secret.java:1000000)', 'at java.lang.Test.call(Secret.java:1) PRIVATE',
                      'at java.lang.Test.' + 'm' * 65 + '(Secret.java:1)',
                      'at java.lang.Test.call(Secret.java:1)\x00'):
            refused = helper.gradle_failure_projection(('Caused by: java.lang.RuntimeException: PRIVATE\n' + frame + '\n').encode(),
                                                       work, project_raw, verification)
            self.assertEqual(refused['frames'], [])
        # Worst-size admitted context must trim optional facts without dropping
        # everything into an unavailable projection. Preserve deepest causes.
        long_class = 'org.gradle.' + ('A' * 63 + '.') * 3 + 'B' * 18
        saturated = []
        for index in range(18):
            saturated += ['Caused by: ' + long_class + ': PRIVATE',
                'at ' + long_class + '.' + 'm' * 64 + '(' + 'F' * 96 + '.java:' + str(index + 1) + ')',
                'at ' + long_class + '.' + 'n' * 64 + '(' + 'G' * 96 + '.kt:' + str(index + 1) + ')']
        projection_ast = next(n for n in ast.parse((ROOT / 'desktop/tools/macos_android_dependency_preparation.py').read_bytes()).body
                              if isinstance(n, ast.FunctionDef) and n.name == 'gradle_failure_projection')
        source_literals = {n.targets[0].id: ast.literal_eval(n.value) for n in projection_ast.body
                           if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                           and n.targets[0].id in ('templates', 'symbols')}
        saturated += ['Context: ' + phrase for phrase, _ in source_literals['templates']]
        saturated += ['Context: ' + symbol for symbol in sorted(source_literals['symbols'], key=len, reverse=True)]
        import xml.etree.ElementTree as ET
        coordinates = [':'.join(node.attrib[k] for k in ('group', 'name', 'version'))
                       for node in ET.fromstring(verification).findall('{*}components/{*}component')]
        saturated += ['Context: ' + coordinate for coordinate in sorted(coordinates, key=len, reverse=True)[:8]]
        long_lines = []
        for name, body in json.loads(project_raw)['files'].items():
            if name.removeprefix('project/') in ('build.gradle', 'settings.gradle', 'app/build.gradle', 'app/src/main/AndroidManifest.xml'):
                for number, line in enumerate(base64.b64decode(body).decode().splitlines(), 1):
                    long_lines.append((len(line), name.removeprefix('project/'), number))
        saturated += [str(work / 'run/project' / name) + ':' + str(number)
                      for _, name, number in sorted(long_lines, reverse=True)[:8]]
        stdout_tasks = ''.join('> Task :app:' + 'T' * 94 + str(i) + ' FAILED\n' for i in range(8)).encode()
        saturated_value = helper.gradle_failure_projection(('\n'.join(saturated) + '\n').encode(), work, project_raw, verification,
                                                          stdout=stdout_tasks)
        self.assertLessEqual(len(helper.encoded(saturated_value)), (12 << 10) - 512)
        self.assertEqual(saturated_value['recognition'], 'recognized-public-facts')
        self.assertTrue(saturated_value['scan']['factsTruncated'])
        self.assertEqual(saturated_value['causes'][-1]['index'], 18)
        self.assertEqual([r['causeIndex'] for r in saturated_value['frames']], [17, 17, 18, 18])
        self.assertEqual(len(saturated_value['tasks']), 8)
        self.assertNotIn('PRIVATE', helper.encoded(saturated_value).decode())
        unknown = helper.gradle_failure_projection(b'PRIVATE-ONLY\nCaused by: com.private.Hidden: PRIVATE\n', work, project_raw, verification)
        self.assertEqual(unknown['recognition'], 'no-allowlisted-detail')
        self.assertEqual(unknown['scan']['unknownCauses'], 1)
        self.assertNotIn('PRIVATE', helper.encoded(unknown).decode())
        malformed = helper.gradle_failure_projection(b'x' * 4097 + b'\n\xff\n', work, project_raw, verification)
        self.assertEqual((malformed['scan']['longLines'], malformed['scan']['invalidLines']), (1, 1))
        truncated = helper.gradle_failure_projection(b'x\n' * 4097, work, project_raw, verification)
        self.assertEqual(truncated['scan']['lines'], 4096); self.assertTrue(truncated['scan']['inputTruncated'])
        with self.assertRaisesRegex(helper.Refused, '^gradle-diagnostic-input-bound$'):
            helper.gradle_failure_projection(b'x' * ((2 << 20) + 1), work, project_raw, verification)
        with self.assertRaisesRegex(helper.Refused, '^gradle-diagnostic-public-source$'):
            helper.gradle_failure_projection(b'x', work, b'PRIVATE-SOURCE', verification)
        # A parser interruption yields a finite unavailable projection; a failed
        # publisher is swallowed without authorizing task success or new reads.
        saved_projection, saved_publish = helper.gradle_failure_projection, helper.publish_preparation
        emitted = []
        def interrupted(*args, **kwargs): raise KeyboardInterrupt('PRIVATE-PARSER-FAULT')
        helper.gradle_failure_projection = interrupted
        helper.publish_preparation = lambda work, name, raw, clock: emitted.append((name, json.loads(raw)))
        result = types.SimpleNamespace(returncode=1, stderr=stderr, stdout=b'')
        try:
            helper.publish_gradle_failure(work, result, project_raw, verification, Clock())
            self.assertEqual(emitted[0][0], 'evidence/gradle-failure.json')
            self.assertEqual(emitted[0][1]['recognition'], 'projection-unavailable')
            self.assertFalse(emitted[0][1]['originalTaskSuccess'])
            helper.publish_preparation = interrupted
            helper.publish_gradle_failure(work, result, project_raw, verification, Clock())
        finally: helper.gradle_failure_projection, helper.publish_preparation = saved_projection, saved_publish
