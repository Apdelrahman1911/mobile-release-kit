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
        self.assertEqual(constants['RUN_SCOPE'], 'prepare-b')
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
        acquisition = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Acquisition')
        seal = next(n for n in acquisition.body if isinstance(n, ast.FunctionDef) and n.name == 'seal')
        seal_source = ast.get_source_segment(source, seal)
        self.assertLess(seal_source.index("'osx-aapt2-member'"), seal_source.index('self.seal_sdk_root()'))
        self.assertLess(seal_source.index('self.seal_sdk_root()'), seal_source.index('directories = encoded(self.directories)'))
        self.assertNotIn('self.parent(', seal_source[seal_source.index('self.seal_sdk_root()'):])
        self.assertIn("'pythonExecutable': python_executable", source)
        self.assertIn("value['pythonExecutable'] == observed_python_executable()", source)
        # Fixed B argv remains the exact A command minus one write flag.
        helper = fixture_module('desktop/tools/macos_android_dependency_preparation.py', '_mrk_b_argv_data')
        source_nomination = helper.B_DATA
        self.assertIs(helper.admit_b_nomination(source_nomination), source_nomination)
        self.assertNotIn('work', source_nomination)
        work = Path('/inert/work')
        a_env, a_command, a_jdk = helper.arguments(work)
        b_env, b_command, b_jdk = helper.b_arguments(work)
        self.assertEqual((a_env, a_jdk), (b_env, b_jdk))
        self.assertEqual(b_command, [arg for arg in a_command if arg != '--write-locks'])
        self.assertEqual(b_command[-3:], ['--dependency-verification', 'strict', ':app:bundleRelease'])
        self.assertNotIn('--write-locks', b_command)
        self.assertFalse(any(arg.startswith(('--write-locks', '--update-locks', '--write-verification-metadata'))
                             for arg in b_command))
        self.assertEqual(helper.RUN_SCOPE, 'prepare-b')
        helper.N = types.SimpleNamespace()
        helper.B_DATA = None
        try:
            for operation in (helper.prepare, helper.acquire, helper.cleanup):
                with self.subTest(operation=operation.__name__), self.assertRaisesRegex(helper.Refused, '^b-data-not-nominated$'):
                    operation(work, private=object())
        finally:
            helper.B_DATA = source_nomination
        self.assertIs(helper.B_DATA, source_nomination)
        for name in ('main',):
            function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
            self.assertFalse(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                                 and n.func.id in ('read_b_inputs', 'b_arguments', 'b_materialize_locks', 'b_input_statement')
                                 for n in ast.walk(function)))
        for text in ('N.NormalPhase(', 'N.load_normal_owner(SOURCE)', 'C.compile_archive(',
                     'capture.consume_rows(self.terminal_row)', 'self.verify_binding()',
                     "'unsupported-vendor-alias'", 'os.O_NOFOLLOW', 'os.O_EXCL',
                     "'--dependency-verification', 'strict', '--write-locks', ':app:bundleRelease'",
                     "'--max-workers=2'", "'-Xmx2048m'", 'PHASE_SECONDS = 1200',
                     'ACQUISITION_SECONDS = 900', "command, 900, 2 << 20", 'READ_BYTES = 8 << 30',
                     'shutil.rmtree.avoids_symlink_attacks', 'shutil.rmtree(leaf, dir_fd=fd)'):
            self.assertIn(text, source)
        for text in ('sdkmanager', 'subprocess.run(', 'extractall(', 'gradle --stop'):
            self.assertNotIn(text, source)
        workflow = (ROOT / '.github/workflows/desktop-macos-android-dependencies.yml').read_text()
        self.assertIn('branches: [verify/desktop-macos-android-dependencies]', workflow)
        self.assertIn('runs-on: macos-26', workflow)
        self.assertIn('timeout-minutes: 53', workflow)
        self.assertIn('2+3+3+1+37+2+2=50', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('python-version: \'3.14.7\'', workflow)
        self.assertEqual(workflow.count('${{ steps.work.outputs.root }}/evidence/inventory-drift.json\n'), 1)
        self.assertNotIn("macos_android_dependency_preparation.py observe-sdk", workflow)
        self.assertIn("macos_android_dependency_preparation.py prepare-b", workflow)
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
            def invoke(changes=None, *, late=None, publication=None, shared=False):
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
                supplied = Clock(30) if shared else None
                returned, failure = None, None
                try:
                    returned = helper.observe_sdk_current_use(Path('/case/inert-output'), private=admitted, clock=supplied)
                    if shared:
                        self.assertIs(clocks[0], supplied)
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
            shared_value, shared_error, shared_reads, shared_publications, shared_clocks = invoke(shared=True)
            self.assertIsNone(shared_error)
            self.assertEqual(shared_value, returned)
            self.assertEqual(shared_reads, expected_reads)
            self.assertEqual(shared_publications, [returned])
            self.assertEqual(len(shared_clocks), 1)
            self.assertTrue(shared_clocks[0].finished)
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
                helper.sys = types.SimpleNamespace(argv=['fixed-source', 'observe-sdk' if kind == 'wrong-scope' else 'prepare-b'])
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
                    self.assertEqual(leaves, ['prepare-b-failure.json'])
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
                    self.assertEqual(value['scope'], 'prepare-b')
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
            (work / 'evidence').mkdir(mode=0o700)
            with self.assertRaisesRegex(helper.Refused, '^preparation-output-bound$'):
                helper.publish_preparation(work, 'evidence/inventory-drift.json', b'x' * ((1 << 20) + 1), clock=Clock())
            self.assertFalse((work / 'evidence/inventory-drift.json').exists())
            helper.publish_preparation(work, 'evidence/inventory-drift.json', b'x' * (1 << 20), clock=Clock())
            self.assertEqual((work / 'evidence/inventory-drift.json').read_bytes(), b'x' * (1 << 20))

        # Tiny real readonly lifecycle; no archives or vendor code. The exact
        # source call-order assertion above covers placement after file sealing.
        readonly = fixture_module('desktop/tools/macos_android_dependency_preparation.py', '_mrk_sdk_readonly_data')
        readonly.N = types.SimpleNamespace(PhaseClock=Clock); readonly.P = transport
        with tempfile.TemporaryDirectory(prefix='sdk-sealed-', dir=scratch) as temporary:
            work = Path(temporary); (work / 'tools').mkdir(mode=0o700)
            a = readonly.Acquisition(work)
            for relative in ('sdk/package/payload', 'gradle/placeholder'):
                held, _ = a.parent(relative); readonly.close_chain(*held)
            sdk = work / 'tools/sdk'; payload = sdk / 'package/payload'
            payload.write_bytes(b'pin'); payload.chmod(0o444)
            a.roster = [{'path': 'sdk/package/payload', 'bytes': 3, 'sha256': readonly.digest(b'pin'),
                         'identity': list(readonly.nine(payload.stat()))}]
            before = dict(a.directories)
            try:
                a.seal_sdk_root()
                self.assertEqual(stat.S_IMODE(sdk.stat().st_mode), 0o500)
                self.assertEqual(a.directories['sdk'], list(readonly.nine(sdk.stat())[:5]))
                self.assertEqual({k: v for k, v in a.directories.items() if k != 'sdk'},
                                 {k: v for k, v in before.items() if k != 'sdk'})
                self.assertEqual(payload.read_bytes(), b'pin')
                with self.assertRaises(PermissionError): (sdk / '.knownPackages').write_bytes(b'not-created')
                self.assertFalse((sdk / '.knownPackages').exists())
                for leaf, value in (('tool-roster.json', a.roster), ('directory-roster.json', a.directories)):
                    (work / leaf).write_bytes(readonly.encoded(value)); (work / leaf).chmod(0o600)
                self.assertEqual(readonly.tool_post(work, Clock()),
                    readonly.digest(readonly.encoded(a.roster) + readonly.encoded(a.directories)))
                sdk.chmod(0o700)
                with self.assertRaisesRegex(readonly.Refused, '^tool-directory-post$'): readonly.tool_post(work, Clock())
                (sdk / '.knownPackages').write_bytes(b'inert-unexpected'); sdk.chmod(0o500)
                with self.assertRaisesRegex(readonly.Refused, '^tool-namespace-changed$'): readonly.tool_post(work, Clock())
            finally: sdk.chmod(0o700)
        for mutation in ('symlink', 'mode', 'identity', 'named-swap', 'chmod', 'close', 'chmod-and-close'):
            with self.subTest(sdk_seal=mutation), tempfile.TemporaryDirectory(prefix='sdk-seal-fault-', dir=scratch) as temporary:
                work = Path(temporary); (work / 'tools').mkdir(mode=0o700); sdk = work / 'tools/sdk'
                sdk.mkdir(mode=0o700); outside = work / 'outside'; outside.mkdir(mode=0o700)
                (outside / 'sentinel').write_bytes(b'unchanged')
                a = readonly.Acquisition(work); a.directories = {'sdk': list(readonly.nine(sdk.stat())[:5])}
                if mutation == 'symlink': sdk.rmdir(); sdk.symlink_to(outside, target_is_directory=True)
                if mutation == 'mode': sdk.chmod(0o500)
                if mutation == 'identity': a.directories['sdk'][1] += 1
                opened, closed, chmods = [], [], []; original_os = readonly.os
                primary = OSError('inert-chmod-primary')
                def tracked_open(*args, **kwargs):
                    fd = os.open(*args, **kwargs); opened.append(fd); return fd
                def tracked_chmod(fd, mode):
                    chmods.append(mode)
                    if mutation in ('chmod', 'chmod-and-close'): raise primary
                    os.fchmod(fd, mode)
                    if mutation == 'named-swap': sdk.rename(work / 'tools/retained-sdk'); sdk.mkdir(mode=0o700)
                def tracked_close(fd):
                    closed.append(fd); os.close(fd)
                    if mutation in ('close', 'chmod-and-close') and fd == opened[-1]:
                        raise OSError('inert-consuming-close')
                readonly.os = types.SimpleNamespace(**dict(vars(os), open=tracked_open, close=tracked_close, fchmod=tracked_chmod))
                try:
                    with self.assertRaises((OSError, readonly.Refused)) as caught: a.seal_sdk_root()
                    if mutation in ('chmod', 'chmod-and-close'): self.assertIs(caught.exception, primary)
                    if mutation == 'named-swap':
                        self.assertIsInstance(caught.exception, readonly.Refused)
                        self.assertEqual(str(caught.exception), 'sdk-seal-post')
                finally:
                    readonly.os = original_os
                    rescued = [fd for fd in opened if fd not in closed]
                    for fd in rescued: os.close(fd)
                    for path in (sdk, work / 'tools/retained-sdk'):
                        if path.exists() and not path.is_symlink(): path.chmod(0o700)
                self.assertEqual(rescued, []); self.assertEqual(len(closed), len(set(closed)))
                self.assertEqual(set(opened), set(closed))
                if mutation in ('symlink', 'mode', 'identity'): self.assertEqual(chmods, [])
                self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o700)
                self.assertEqual((outside / 'sentinel').read_bytes(), b'unchanged')

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
                helper.sys = types.SimpleNamespace(argv=['fixed', 'prepare-b'])
                helper.context = lambda: expected; helper.load = lambda *args: types.SimpleNamespace()
                helper.prepare = lambda work, private: FinalClock()
                try: result = helper.main()
                finally:
                    helper.admit_work, helper.os, helper.sys, helper.context, helper.load, helper.prepare = original
                    for private in adopted:
                        if private['fds']: helper.close_chain(private['fds'], private['originals'])
                self.assertEqual(result, 78 if late else 0)
                self.assertEqual(finished, [True])

        # Actual tiny tool namespace: no tool bodies are read, including the
        # unexpected symlink. Only the exact public cache name is published.
        namespace = fixture_module('desktop/tools/macos_android_dependency_preparation.py', '_mrk_a_namespace_data')
        details = {}
        for name in ('.knownPackages', 'private-token-α'):
            with self.subTest(namespace=name), tempfile.TemporaryDirectory(prefix='a-namespace-', dir=scratch) as temporary:
                work = Path(temporary); tools = work / 'tools'; tools.mkdir(mode=0o700)
                sdk = tools / 'sdk'; sdk.mkdir(mode=0o700)
                (sdk / name).symlink_to('/never-read/private-content')
                for leaf, value in (('tool-roster.json', []),
                                    ('directory-roster.json', {'sdk': list(namespace.nine(sdk.stat())[:5])})):
                    (work / leaf).write_bytes(namespace.encoded(value)); (work / leaf).chmod(0o600)
                original_read = namespace.read; reads = []
                def roster_read(path, limit, *, clock):
                    reads.append(path.name); return original_read(path, limit, clock=clock)
                namespace.read = roster_read
                try:
                    with self.assertRaisesRegex(namespace.Refused, '^tool-namespace-changed$') as caught:
                        namespace.tool_post(work, Clock(1))
                finally: namespace.read = original_read
                detail = caught.exception.tool_namespace; details[name] = detail
                relative = ('sdk/' + name).encode('utf-8')
                self.assertEqual(reads, ['tool-roster.json', 'directory-roster.json'])
                self.assertEqual(detail, {'change': 'unexpected', 'toolFamily': 'sdk',
                    'relativeBytes': len(relative), 'relativeSha256': namespace.digest(relative),
                    'publicPath': 'sdk/.knownPackages' if name == '.knownPackages' else None})
                self.assertNotIn(b'private-token', namespace.encoded(detail))
                self.assertNotIn(str(work).encode(), namespace.encoded(detail))
                # Duplicate recognition remains bounded and refuses identically.
                original_os = namespace.os
                namespace.os = types.SimpleNamespace(**dict(vars(os), walk=lambda *a, **k: [(str(tools), ['sdk', 'sdk'], [])]))
                try:
                    with self.assertRaisesRegex(namespace.Refused, '^tool-namespace-changed$') as duplicate:
                        namespace.tool_post(work, Clock(1))
                    self.assertEqual(duplicate.exception.tool_namespace['change'], 'duplicate')
                finally: namespace.os = original_os

        # The real retained-FD publisher admits only the closed optional shape;
        # even publication failure leaves wrapper78 and consumes all originals.
        for mutation in ('none', 'private', 'extra', 'bad-path', 'bad-size', 'bad-hash', 'bad-family', 'bad-change', 'wrong-code', 'publish-failure'):
            with self.subTest(namespace_publication=mutation), tempfile.TemporaryDirectory(prefix='a-namespace-main-', dir=scratch) as temporary:
                work = Path(temporary); adopted = []
                detail = dict(details['private-token-α' if mutation == 'private' else '.knownPackages'])
                if mutation == 'extra': detail['raw'] = 'private-token'
                if mutation == 'bad-path': detail['publicPath'] = 'sdk/private-token'
                if mutation == 'bad-size': detail['relativeBytes'] = True
                if mutation == 'bad-hash': detail['relativeSha256'] = '0' * 64
                if mutation == 'bad-family': detail['toolFamily'] = 'private-token'
                if mutation == 'bad-change': detail['change'] = 'private-token'
                primary = namespace.Refused('another-original-failure' if mutation == 'wrong-code' else 'tool-namespace-changed')
                primary.tool_namespace = detail
                original = (namespace.admit_work, namespace.os, namespace.sys, namespace.context,
                            namespace.load, namespace.prepare, namespace.publish_json)
                def admit(path):
                    private = original[0](work); adopted.append(private); return dict(private, path=expected)
                def refuse(work, *, private): raise primary
                def failed_publish(*args): raise KeyboardInterrupt('inert-publication-failure')
                namespace.admit_work = admit
                namespace.os = types.SimpleNamespace(**dict(vars(os), environ={'MRK_ANDROID_PREPARATION_WORK': str(expected)}))
                namespace.sys = types.SimpleNamespace(argv=['fixed', 'prepare-b'])
                namespace.context = lambda: expected; namespace.load = lambda *args: types.SimpleNamespace()
                namespace.prepare = refuse
                if mutation == 'publish-failure': namespace.publish_json = failed_publish
                try: result = namespace.main()
                finally:
                    (namespace.admit_work, namespace.os, namespace.sys, namespace.context,
                     namespace.load, namespace.prepare, namespace.publish_json) = original
                    remaining = [fd for private in adopted for fd in private['fds']]
                    for private in adopted:
                        if private['fds']: namespace.close_chain(private['fds'], private['originals'])
                self.assertEqual(result, 78); self.assertEqual(remaining, [])
                if mutation == 'publish-failure':
                    self.assertEqual(list(work.iterdir()), []); continue
                raw = (work / 'prepare-b-failure.json').read_bytes(); report = json.loads(raw)
                self.assertLessEqual(len(raw), 4096); self.assertNotIn(b'private-token', raw)
                self.assertNotIn(str(work).encode(), raw)
                self.assertEqual(report['reason'], str(primary))
                self.assertFalse(report['nativeOrTaskSuccess']); self.assertFalse(report['cleanupAuthorized'])
                if mutation in ('none', 'private'): self.assertEqual(report['toolNamespace'], detail)
                else: self.assertNotIn('toolNamespace', report)

    def test_a_actual_report_and_complete_cleanup_receipt_reject_partial_evidence(self):
        self.assertNotEqual(os.getuid(), 0)
        helper = fixture_module('desktop/tools/macos_android_dependency_preparation.py', '_mrk_a_receipt_data')
        normal = fixture_module('desktop/tools/macos_normal_ui_runner.py', '_mrk_a_record_data')
        helper.N = normal
        scratch = Path(os.environ['TMPDIR']); sha = 'c' * 40
        # Synthetic custody negatives remain separate from the fixed real A
        # nomination, which is read through the actual input boundary below.
        b = fixture_module('desktop/tools/macos_android_dependency_preparation.py', '_mrk_b_input_data')
        b.N = normal
        source_nomination = b.B_DATA
        self.assertIs(b.admit_b_nomination(source_nomination), source_nomination)
        class BClock:
            def check(self): return 1
        saved_read = b.read
        b.read = lambda *args, **kwargs: self.fail('unnominated B reached a file read')
        try:
            with self.assertRaisesRegex(b.Refused, '^b-data-not-nominated$'):
                b.read_b_inputs(Path('/absent'), None, b'', b'', (), BClock())
        finally: b.read = saved_read
        synthetic = {'schemaVersion': 1, 'source': 'a' * 40, 'tree': 'b' * 40, 'run': 1, 'attempt': 1,
            'job': 1, 'artifactId': 1, 'artifactSha256': 'c' * 64, 'reviewSha256': 'd' * 64,
            'pythonExecutable': '/inert/public/python',
            'resources': {name: [1, 'e' * 64] for name in b.B_DATA_ROSTER}}
        self.assertEqual(b.admit_b_nomination(synthetic), synthetic)
        self.assertNotIn('work', synthetic)
        statement = b.b_input_statement(synthetic)
        self.assertTrue(statement['locksAreReviewedAInputs'])
        self.assertFalse(statement['locksAreOriginalGradleTaskOutputs'])
        for changed in (dict(synthetic, source='x' * 40), dict(synthetic, run=True),
                        dict(synthetic, pythonExecutable='/inert/../python'), dict(synthetic, work='/private/other'),
                        dict(synthetic, extra=True), dict(synthetic, resources={})):
            with self.assertRaises(b.Refused): b.admit_b_nomination(changed)
        with tempfile.TemporaryDirectory(prefix='b-original-', dir=scratch) as temporary:
            root = Path(temporary)
            data_root = root / 'source/desktop/tools/android_dependency_preparation_data/phase-a'
            data_root.mkdir(parents=True, mode=0o700)
            originals = {}; bodies = {}
            for name in b.B_DATA_ROSTER:
                body = ('inert-' + name).encode(); (data_root / name).write_bytes(body); (data_root / name).chmod(0o600)
                bodies[name], originals[name] = b.read(data_root / name, b.B_DATA_ROSTER[name], clock=BClock())
            nominated = dict(synthetic, resources={name: [len(raw), b.digest(raw)] for name, raw in bodies.items()})
            inputs = {'nomination': nominated, 'raw': bodies, 'originals': originals}
            b.b_input_post(root / 'source', inputs, BClock())
            # Same bytes in a replaced inode are not the same admitted original.
            path = data_root / 'inventory.json'; replacement = data_root / 'replacement'
            replacement.write_bytes(path.read_bytes()); replacement.chmod(0o600); replacement.replace(path)
            with self.assertRaisesRegex(b.Refused, '^b-input-original-post$'):
                b.b_input_post(root / 'source', inputs, BClock())
            (root / 'run/project/app').mkdir(parents=True, mode=0o700)
            lock_originals = b.b_materialize_locks(root, inputs, BClock())
            b.b_lock_post(root, lock_originals, BClock())
            # JSON receipts retain the same nine-field identity, not tuple type.
            b.b_lock_post(root, json.loads(b.encoded(lock_originals)), BClock())
            for invalid in ({}, dict(lock_originals, extra=()),
                            dict(lock_originals, **{'app/gradle.lockfile': [[], '0' * 64]})):
                with self.assertRaises(b.Refused):
                    b.b_lock_post(root, invalid, BClock())
            path = root / 'run/project/app/gradle.lockfile'; replacement = path.with_name('replacement')
            replacement.write_bytes(path.read_bytes()); replacement.chmod(0o600); replacement.replace(path)
            with self.assertRaisesRegex(b.Refused, '^b-lock-original-post$'):
                b.b_lock_post(root, lock_originals, BClock())
        helper.os = types.SimpleNamespace(**dict(vars(os), environ={'GITHUB_SHA': sha}))
        class Clock:
            def check(self): return 1
        # Real tiny project materialization catches stale decoded-total guards;
        # only path syntax is adapted, and no Gradle/vendor code executes.
        helper.P = types.SimpleNamespace(relative=lambda name: self.assertTrue(
            name and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/'))))
        project_raw = (ROOT / 'desktop/tools/android_dependency_preparation_data/project-v1.json').read_bytes()
        verification = (ROOT / 'desktop/tools/android_dependency_preparation_data/verification-v1.xml').read_bytes()
        # Real reviewed A DATA: no vendor execution or simulated nomination.
        # The existing reader owns exact raw pins, receipt/lock/XML admission
        # and original-FD closure; POST must retain those same four originals.
        real_inputs = b.read_b_inputs(ROOT, source_nomination, project_raw, verification,
                                      (len(verification), b.digest(verification)), BClock())
        self.assertIs(real_inputs['nomination'], source_nomination)
        self.assertEqual(real_inputs['receipt']['source'], source_nomination['source'])
        self.assertFalse(real_inputs['receipt']['protectedRegistration'])
        self.assertFalse(real_inputs['receipt']['uiQualification'])
        self.assertEqual(set(real_inputs['originals']), set(b.B_DATA_ROSTER))
        self.assertTrue(all(len(identity) == 9 and stat.S_ISREG(identity[2])
                            for identity in real_inputs['originals'].values()))
        self.assertEqual({name: [len(raw), b.digest(raw)] for name, raw in real_inputs['raw'].items()},
                         source_nomination['resources'])
        self.assertEqual(len(real_inputs['inventoryRows']), 345)
        self.assertEqual(sum(row[4] for row in real_inputs['inventoryRows']), 209839014)
        self.assertEqual(sum(len(real_inputs['raw'][name]) for name in
                             ('buildscript-gradle.lockfile', 'app-gradle.lockfile')), 6892)
        root_states, app_states = real_inputs['lockStates']
        self.assertEqual(tuple(name for name, _ in root_states), ('classpath',))
        self.assertEqual(len(root_states[0][1]), 123)
        self.assertIn(('com.android.tools.build', 'gradle', '8.9.2'), root_states[0][1])
        self.assertEqual(app_states, tuple((name, ()) for name in
            ('androidApis', 'androidJdkImage', 'lintChecks', 'releaseAnnotationProcessorClasspath',
             'releaseCompileClasspath', 'releaseReverseMetadataValues', 'releaseRuntimeClasspath')))
        b.b_input_post(ROOT, real_inputs, BClock())
        self.assertIs(b.B_DATA, source_nomination)
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
            # The pure prior-A predicate uses supplied A context, not today's
            # GITHUB_SHA/Python path or current uid/inodes as old authority.
            nominated = dict(synthetic, source=sha, pythonExecutable=sys.executable)
            old_value = json.loads(json.dumps(value))
            # No public old private-work path exists. These vendor hashes are
            # opaque pinned DATA, not an independently reconstructed command.
            for index in (3, 4, 5): old_value['commands'][index]['argvSha256'] = str(index) * 64
            old_raw = b.encoded(old_value)
            nominated['resources'] = dict(nominated['resources'], **{'receipt.json': [len(old_raw), b.digest(old_raw)]})
            self.assertEqual(b.admit_a_receipt(old_raw, nominated, b'project', b'verification'), old_value)
            with self.assertRaisesRegex(b.Refused, '^b-a-command-original$'):
                b.admit_a_receipt(old_raw, dict(nominated, pythonExecutable='/inert/other/python'), b'project', b'verification')
            wrong = json.loads(old_raw); wrong['commands'][5]['returncode'] = 1
            wrong_raw = b.encoded(wrong)
            wrong_nomination = dict(nominated, resources=dict(nominated['resources'], **{'receipt.json': [len(wrong_raw), b.digest(wrong_raw)]}))
            with self.assertRaisesRegex(b.Refused, '^b-a-command-original$'):
                b.admit_a_receipt(wrong_raw, wrong_nomination, b'project', b'verification')
            for index, invalid_hash in ((0, '0' * 64), (2, '0' * 64), (3, ''), (4, None), (5, 'g' * 64)):
                invalid_receipt = json.loads(old_raw); invalid_receipt['commands'][index]['argvSha256'] = invalid_hash
                invalid_raw = b.encoded(invalid_receipt)
                invalid_nomination = dict(nominated, resources=dict(nominated['resources'],
                    **{'receipt.json': [len(invalid_raw), b.digest(invalid_raw)]}))
                with self.subTest(old_argv=index), self.assertRaisesRegex(b.Refused, '^b-a-command-original$'):
                    b.admit_a_receipt(invalid_raw, invalid_nomination, b'project', b'verification')
            with self.assertRaisesRegex(b.Refused, '^b-a-receipt-pin$'):
                b.admit_a_receipt(old_raw + b' ', nominated, b'project', b'verification')
            # Real fixed-four reader + all three DATA predicates on tiny synthetic
            # inputs. These constructed receipts are NOT genuine A evidence.
            input_receipt = json.loads(old_raw)
            input_receipt.update(fixtureSha256=b.digest(project_raw), verificationSha256=b.digest(verification))
            ns = {'v': 'https://schema.gradle.org/dependency-verification'}
            first_component = b.ET.fromstring(verification).find('v:components/v:component', ns)
            first_artifact = first_component.find('v:artifact', ns)
            input_row = dict(first_component.attrib, artifact=first_artifact.attrib['name'], bytes=1,
                             sha256=first_artifact.find('v:sha256', ns).attrib['value'])
            input_inventory = {'classification': 'actual-cache-artifacts-not-independent-task-resolution-graph',
                               'locksAreOriginalGradleTaskOutputs': True, 'rows': [input_row]}
            input_header = (b'# This is a Gradle generated file for dependency locking.\n'
                            b'# Manual edits can break the build and are not advised.\n'
                            b'# This file is expected to be part of source control.\n')
            input_raw = {'receipt.json': b.encoded(input_receipt), 'inventory.json': b.encoded(input_inventory),
                         'buildscript-gradle.lockfile': input_header + b'com.android.tools.build:gradle:8.9.2=classpath\nempty=unusedRoot\n',
                         'app-gradle.lockfile': input_header + b'empty=unusedApp\n'}
            input_nomination = dict(nominated, resources={name: [len(raw), b.digest(raw)] for name, raw in input_raw.items()})
            input_source = work / 'fixed-input-source'
            input_directory = input_source / 'desktop/tools/android_dependency_preparation_data/phase-a'
            input_directory.mkdir(parents=True, mode=0o700)
            for name, raw in input_raw.items():
                (input_directory / name).write_bytes(raw); (input_directory / name).chmod(0o600)
            input_pin = (len(verification), b.digest(verification))
            admitted_inputs = b.read_b_inputs(input_source, input_nomination, project_raw, verification, input_pin, BClock())
            self.assertEqual(admitted_inputs['raw'], input_raw)
            self.assertEqual(set(admitted_inputs['originals']), set(b.B_DATA_ROSTER))
            self.assertEqual(admitted_inputs['lockStates'],
                ((('classpath', (('com.android.tools.build', 'gradle', '8.9.2'),)), ('unusedRoot', ())), (('unusedApp', ()),)))
            self.assertEqual(admitted_inputs['inventoryRows'],
                (tuple(input_row[key] for key in ('group', 'name', 'version', 'artifact', 'bytes', 'sha256')),))
            b.b_input_post(input_source, admitted_inputs, BClock())
            wrong_pin = dict(input_nomination, resources=dict(input_nomination['resources'],
                **{'inventory.json': [len(input_raw['inventory.json']), '0' * 64]}))
            with self.assertRaisesRegex(b.Refused, '^b-input-original-pin$'):
                b.read_b_inputs(input_source, wrong_pin, project_raw, verification, input_pin, BClock())
            unreviewed_lock = input_raw['buildscript-gradle.lockfile'].replace(b'empty=unusedRoot',
                b'unreviewed.synthetic:must-refuse:1.0=classpath\nempty=unusedRoot')
            (input_directory / 'buildscript-gradle.lockfile').write_bytes(unreviewed_lock)
            unreviewed_nomination = dict(input_nomination, resources=dict(input_nomination['resources'],
                **{'buildscript-gradle.lockfile': [len(unreviewed_lock), b.digest(unreviewed_lock)]}))
            with self.assertRaisesRegex(b.Refused, '^b-lock-unreviewed-coordinate$'):
                b.read_b_inputs(input_source, unreviewed_nomination, project_raw, verification, input_pin, BClock())
            self.assertIs(b.B_DATA, source_nomination)
            value['phase'] = 'B'; value['status'] = 'closed-awaiting-distinct-b-data-review'
            _, locked_task, _ = helper.b_arguments(work)
            value['commands'][5]['role'] = 'android-dependency-locked-task'
            value['commands'][5]['argvSha256'] = helper.digest(normal.encoded(locked_task))
            cleanup_inputs = {'nomination': synthetic, 'originals': {name: (1,) * 9 for name in helper.B_DATA_ROSTER},
                              'inventoryRows': ()}
            value.update(aInputStatement=helper.b_input_statement(synthetic),
                         aInputOriginals={name: [1] * 9 for name in helper.B_DATA_ROSTER},
                         lockOriginals={relative: [[1] * 9, synthetic['resources'][resource][1]]
                             for resource, relative in (('buildscript-gradle.lockfile', 'buildscript-gradle.lockfile'),
                                                        ('app-gradle.lockfile', 'app/gradle.lockfile'))},
                         inventorySha256=helper.digest(helper.encoded(helper.b_inventory_document(cleanup_inputs))))
            helper.read_b_inputs = lambda *args: cleanup_inputs
            helper.b_lock_post = lambda *args: None
            helper.b_input_post = lambda *args: None
            helper.acquisition_receipt = lambda work, clock: ({'sdkObservationSha256': '3' * 64, 'toolRosterSha256': '1' * 64}, '2' * 64)
            helper.resources = lambda: (b'project', b'verification')
            helper.read = lambda path, limit, clock: (helper.encoded(helper.b_inventory_document(cleanup_inputs)), None) if path == work / 'evidence/inventory.json' else ((ROOT / path.relative_to(helper.SOURCE)).read_bytes(), None)
            helper.cleanup_receipt(work, value, Clock())
            mutations = [('phase', 'A'), ('workflow', 'wrong'), ('source', 'e' * 40), ('wrapperReturncodeRequired', False),
                         ('toolRosterSha256', '9' * 64), ('fixtureSha256', '9' * 64), ('commands', records[:-1]),
                         ('aInputStatement', {}), ('aInputOriginals', {}), ('inventorySha256', '9' * 64)]
            for key, invalid in mutations:
                with self.subTest(field=key), self.assertRaises(helper.Refused):
                    helper.cleanup_receipt(work, dict(value, **{key: invalid}), Clock())
            for relative in value['lockOriginals']:
                modified = json.loads(json.dumps(value)); modified['lockOriginals'][relative][1] = '0' * 64
                with self.subTest(lock_input=relative), self.assertRaisesRegex(helper.Refused, '^cleanup-b-lock-input-binding$'):
                    helper.cleanup_receipt(work, modified, Clock())
            for key, invalid in (('argvSha256', 'f' * 64), ('roleCapSeconds', 901), ('timeoutSeconds', 0),
                                 ('returncode', False), ('stdoutBytes', (2 << 20) + 1)):
                modified = json.loads(json.dumps(value)); modified['commands'][5][key] = invalid
                with self.subTest(record=key), self.assertRaises(helper.Refused): helper.cleanup_receipt(work, modified, Clock())
            for change in ({'deadlineNs': '1'}, {'beforePublicationNs': str(1200 * 1000000000)},
                           {'postCloseDeadlineRequired': False}):
                modified = dict(value, phaseClock=dict(value['phaseClock'], **change))
                with self.subTest(clock=change), self.assertRaises(helper.Refused): helper.cleanup_receipt(work, modified, Clock())

        # Fixed successful-disposal gate plus real SDK/roster/FD restoration.
        # The receipt validator above is exercised separately with full inert
        # records; here only that established predicate is an inert adapter.
        disposal = fixture_module('desktop/tools/macos_android_dependency_preparation.py', '_mrk_sdk_disposal_data')
        disposal.N = types.SimpleNamespace(PhaseClock=lambda seconds: Clock(), document=normal.document, pairs=normal.pairs)
        for mutation in ('none', 'wrapper', 'upload', 'receipt', 'digest', 'tools-swap', 'sdk-swap',
                         'sdk-mode', 'sdk-symlink', 'restore-chmod', 'restore-close', 'restore-primary-and-close'):
            with self.subTest(sdk_disposal=mutation), tempfile.TemporaryDirectory(prefix='sdk-disposal-', dir=scratch) as temporary:
                work = Path(temporary); evidence = work / 'evidence'; evidence.mkdir(mode=0o700)
                for leaf in ('archives', 'tools', 'run'): (work / leaf).mkdir(mode=0o700)
                sdk = work / 'tools/sdk'; sdk.mkdir(mode=0o700); sdk.chmod(0o500)
                outside = work / 'outside'; outside.mkdir(mode=0o700); (outside / 'sentinel').write_bytes(b'kept')
                dirs = {'sdk': list(disposal.nine(sdk.stat())[:5])}
                raw_rows, raw_dirs = b'[]', disposal.encoded(dirs)
                for leaf, body in (('tool-roster.json', raw_rows), ('directory-roster.json', raw_dirs)):
                    (work / leaf).write_bytes(body); (work / leaf).chmod(0o600)
                value = {'workIdentity': list(disposal.nine(work.stat())[:5]),
                    'disposalIdentities': {leaf: list(disposal.nine((work / leaf).stat())[:5]) for leaf in ('archives', 'tools', 'run')},
                    'toolRosterSha256': disposal.digest(raw_rows + raw_dirs)}
                if mutation == 'digest': value['toolRosterSha256'] = '0' * 64
                receipt = evidence / 'receipt.json'; receipt.write_bytes(disposal.encoded(value)); receipt.chmod(0o600)
                if mutation == 'tools-swap': (work / 'tools').rename(work / 'old-tools'); (work / 'tools').mkdir(mode=0o700)
                if mutation == 'sdk-swap': sdk.rename(work / 'tools/old-sdk'); sdk.mkdir(mode=0o700); sdk.chmod(0o500)
                if mutation == 'sdk-mode': sdk.chmod(0o700)
                if mutation == 'sdk-symlink': sdk.rmdir(); sdk.symlink_to(outside, target_is_directory=True)
                private = disposal.admit_work(work); opened, closed, chmods, deleted = [], [], [], []
                original = disposal.os, disposal.shutil, disposal.cleanup_receipt, disposal.B_DATA
                fault = OSError('inert-restore-primary')
                def validate(work, value, clock):
                    if mutation == 'receipt': raise disposal.Refused('cleanup-receipt')
                def tracked_open(*args, **kwargs):
                    fd = os.open(*args, **kwargs); opened.append(fd); return fd
                def tracked_chmod(fd, mode):
                    chmods.append(mode)
                    if mutation in ('restore-chmod', 'restore-primary-and-close'): raise fault
                    os.fchmod(fd, mode)
                def tracked_close(fd):
                    closed.append(fd); os.close(fd)
                    # Restrict the consuming fault to the separately adopted SDK
                    # restoration FD; roster readers also use tracked originals.
                    if mutation in ('restore-close', 'restore-primary-and-close') and chmods and fd == opened[-1]:
                        raise OSError('inert-restoration-close')
                def retire(leaf, *, dir_fd):
                    self.assertEqual(chmods, [0o700])
                    deleted.append(leaf); return original[1].rmtree(leaf, dir_fd=dir_fd)
                retire.avoids_symlink_attacks = True
                environment = {'MRK_PREPARATION_WRAPPER_RETURN': '1' if mutation == 'wrapper' else '0',
                               'MRK_PREPARATION_EVIDENCE_UPLOAD': 'failure' if mutation == 'upload' else 'success'}
                disposal.os = types.SimpleNamespace(**dict(vars(os), environ=environment,
                    open=tracked_open, close=tracked_close, fchmod=tracked_chmod))
                disposal.shutil = types.SimpleNamespace(rmtree=retire); disposal.cleanup_receipt = validate
                # Explicit synthetic nomination only for this isolated disposal fixture.
                # Real B input/receipt gates are independently exercised above.
                disposal.B_DATA = synthetic
                test_primary = None
                try:
                    if mutation == 'none': disposal.cleanup(work, private=private)
                    else:
                        with self.assertRaises((OSError, disposal.Refused)) as caught: disposal.cleanup(work, private=private)
                        if mutation in ('restore-chmod', 'restore-primary-and-close'): self.assertIs(caught.exception, fault)
                except BaseException as error:
                    test_primary = error; raise
                finally:
                    disposal.os, disposal.shutil, disposal.cleanup_receipt, disposal.B_DATA = original
                    rescue_failure = None
                    try: disposal.close_chain(private['fds'], private['originals'])
                    except BaseException as error: rescue_failure = error
                    finally:
                        # Each owned temporary mode rescue runs even when a
                        # close or another rescue fails; never mask the test.
                        for path in (sdk, work / 'tools/old-sdk', work / 'old-tools/sdk'):
                            try:
                                if path.exists() and not path.is_symlink(): path.chmod(0o700)
                            except BaseException as error:
                                if rescue_failure is None: rescue_failure = error
                    if test_primary is None and rescue_failure is not None: raise rescue_failure
                # Descriptor numbers are reusable across separate finite reads;
                # assert balanced adoptions only after guaranteed fixture rescue.
                self.assertEqual(len(opened), len(closed))
                self.assertEqual((outside / 'sentinel').read_bytes(), b'kept')
                self.assertTrue(receipt.is_file())
                if mutation == 'none':
                    self.assertEqual(deleted, ['archives', 'tools', 'run'])
                    self.assertEqual(chmods, [0o700])
                    self.assertFalse(any((work / leaf).exists() for leaf in ('archives', 'tools', 'run')))
                else:
                    self.assertEqual(deleted, [])
                    if not mutation.startswith('restore-'): self.assertEqual(chmods, [])
                    self.assertTrue((work / 'archives').is_dir()); self.assertTrue((work / 'run').is_dir())

        # Inert prepare-path adapters prove that the admitted acquisition roster
        # must equal the first live tool POST BEFORE any Java/Gradle entry. These
        # synthetic return values are control-flow DATA, never native receipts.
        flow = fixture_module('desktop/tools/macos_android_dependency_preparation.py', '_mrk_a_roster_flow_data')
        flow_nomination = flow.B_DATA
        class FlowClock:
            def __init__(self, seconds): self.seconds = seconds
            def before_publication(self): return {'inertSeconds': self.seconds}
            def finish(self): pass
        flow.os = types.SimpleNamespace(**dict(vars(os), statvfs=lambda path: types.SimpleNamespace(f_bavail=8 << 30, f_frsize=1),
            environ={k: 'inert' for k in ('GITHUB_REPOSITORY', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'GITHUB_SHA',
                'GITHUB_WORKFLOW_SHA', 'GITHUB_WORKFLOW_REF', 'GITHUB_WORKSPACE', 'RUNNER_ENVIRONMENT',
                'RUNNER_OS', 'RUNNER_ARCH', 'MRK_ANDROID_PREPARATION_WORK')}))
        flow.observe_sdk_current_use = lambda work, private, clock: object()
        flow.admit_sdk_current_use = lambda value: None
        flow.resources = lambda: (b'project', b'verification')
        flow.admit_b_nomination = lambda value: {}
        flow.read_b_inputs = lambda *args: {}
        flow.b_materialize_locks = lambda *args: {}
        flow.b_lock_post = lambda *args: None
        flow.b_input_post = lambda *args: None
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
                            return types.SimpleNamespace(returncode=1 if role == 'android-dependency-locked-task' else 0, stderr=b'inert')
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
                                            'android-dependency-gradle-version', 'android-dependency-locked-task'])
                elif mismatch:
                    with self.assertRaisesRegex(flow.Refused, '^acquisition-live-tool-roster$'):
                        flow.prepare(Path(temporary), private=object())
                    self.assertEqual(calls, ['android-public-tool-acquisition'])
                else:
                    with self.assertRaises(ValueError) as caught: flow.prepare(Path(temporary), private=object())
                    self.assertIs(caught.exception, reached)
                    self.assertEqual(calls, ['android-public-tool-acquisition', 'android-dependency-jdk-version'])

        # Complete B orchestration uses only explicit in-memory tool/reader DATA.
        # Run the actual prepare body, but never a vendor, SDK or network owner.
        # Both late original changes and semantic cache drift forbid a receipt.
        for failure in (None, 'inventory', 'inventory-publisher', 'inventory-clock', 'late-lock', 'late-input', 'early-input', 'early-finish'):
            with self.subTest(b_replay=failure), tempfile.TemporaryDirectory(prefix='b-replay-flow-', dir=scratch) as temporary:
                clocks, events, calls, emitted = [], [], [], []
                counters = {'input': 0, 'lock': 0}
                initial_failure = flow.Refused('inert-b-input-refusal')
                raw_inputs = {'receipt.json': b'inert-receipt', 'inventory.json': b'inert-inventory',
                    'buildscript-gradle.lockfile': b'inert-buildscript', 'app-gradle.lockfile': b'inert-app'}
                nominated_b = dict(synthetic, resources={name: [len(raw), flow.digest(raw)] for name, raw in raw_inputs.items()})
                identities = {name: (1, index, stat.S_IFREG | 0o600, os.getuid(), os.getgid(), 1, len(raw), 1, 1)
                              for index, (name, raw) in enumerate(raw_inputs.items(), 1)}
                input_b = {'nomination': nominated_b, 'raw': raw_inputs, 'originals': identities,
                    'inventoryRows': (('inert.synthetic', 'artifact', '1.0', 'artifact-1.0.jar', 1, 'a' * 64),)}
                lock_b = {relative: (identities[name], flow.digest(raw_inputs[name]))
                          for name, relative in (('buildscript-gradle.lockfile', 'buildscript-gradle.lockfile'),
                                                 ('app-gradle.lockfile', 'app/gradle.lockfile'))}
                class ReplayClock:
                    def __init__(clock, seconds):
                        clock.seconds = seconds; clock.failed = False; clock.finished = False; clock.finishes = 0
                        clocks.append(clock)
                    def check(clock):
                        self.assertFalse(clock.finished or clock.failed)
                    def before_publication(clock):
                        clock.check(); return {'inertSeconds': clock.seconds}
                    def finish(clock):
                        clock.finishes += 1
                        if failure == 'early-finish' and clock.seconds == 30:
                            raise KeyboardInterrupt('inert-secondary-clock-failure')
                        clock.check(); clock.finished = True
                class ReplayPhase:
                    def __init__(phase, owner, environment, cwd, clock):
                        phase.records = []; phase.clock = clock
                    def call(phase, role, argv, cap, limit):
                        phase.clock.check(); calls.append((role, argv, cap, limit))
                        body = (sha + '\n').encode() if role.startswith('source-head') else b''
                        phase.records.append({'role': role, 'returncode': 0, 'timeoutSeconds': cap,
                            'roleCapSeconds': cap, 'outputLimitBytes': limit, 'argvSha256': flow.digest(normal.encoded(argv)),
                            'stdoutBytes': len(body), 'stdoutSha256': flow.digest(body),
                            'stderrBytes': 0, 'stderrSha256': flow.digest(b'')})
                        return types.SimpleNamespace(returncode=0, stdout=body, stderr=b'')
                def input_read(source, nomination, project, xml, pin, clock):
                    self.assertIs(clock, clocks[0]); self.assertEqual(clock.seconds, 30)
                    self.assertEqual(len(clocks), 1); clock.check(); events.append('inputs')
                    if failure in ('early-input', 'early-finish'): raise initial_failure
                    return input_b
                def sdk_observe(work, private, clock):
                    self.assertIs(clock, clocks[0]); self.assertEqual(events, ['inputs'])
                    clock.finish(); events.append('sdk'); return object()
                def input_post(source, inputs, clock):
                    self.assertIs(inputs, input_b); clock.check(); counters['input'] += 1
                    if failure == 'late-input' and counters['input'] == 3:
                        raise flow.Refused('inert-late-input-post')
                def lock_post(work, originals, clock):
                    self.assertIs(originals, lock_b); clock.check(); counters['lock'] += 1
                    if failure == 'late-lock' and counters['lock'] == 3:
                        raise flow.Refused('inert-late-lock-post')
                def source_post(phase, suffix):
                    phase.call('source-head-' + suffix,
                        ['/usr/bin/git', '-C', str(flow.SOURCE), 'rev-parse', 'HEAD'], 10, 4096)
                    phase.call('source-clean-' + suffix,
                        ['/usr/bin/git', '-C', str(flow.SOURCE), 'status', '--porcelain=v1', '--untracked-files=all'], 10, 16384)
                def cache_inventory(work, verification, clock):
                    clock.check(); document = flow.b_inventory_document(input_b)
                    if failure and failure.startswith('inventory'): document['rows'][0]['bytes'] += 1
                    return document
                def capture(work, name, raw, *, clock=None):
                    if name == 'evidence/inventory-drift.json':
                        self.assertIs(clock, clocks[-1])
                        if failure == 'inventory-publisher': raise KeyboardInterrupt('inert-diagnostic-publisher')
                        if failure == 'inventory-clock':
                            clock.failed = True
                            clock.check()
                    if clock is not None: clock.check()
                    self.assertIs(type(raw), bytes); emitted.append((name, raw))
                flow.N = types.SimpleNamespace(PhaseClock=ReplayClock, NormalPhase=ReplayPhase, load_normal_owner=lambda source: object())
                flow.os.environ['GITHUB_SHA'] = sha
                flow.resources = lambda: [b'project', b'verification']
                flow.admit_b_nomination = lambda value: nominated_b
                flow.read_b_inputs = input_read; flow.observe_sdk_current_use = sdk_observe
                flow.b_materialize_locks = lambda *args: lock_b
                flow.b_input_post = input_post; flow.b_lock_post = lock_post
                flow.source_original = source_post; flow.publish_preparation = capture
                flow.acquisition_receipt = lambda work, clock: (
                    {'toolRosterSha256': '1' * 64, 'sdkObservationSha256': '3' * 64}, '2' * 64)
                flow.tool_post = lambda work, clock: '1' * 64
                flow.inventory = cache_inventory
                flow.file_digest = lambda *args: (4, '4' * 64, b'PK\x03\x04')
                returned = caught = None
                try: returned = flow.prepare(Path(temporary), private=object())
                except BaseException as error: caught = error
                receipts = [json.loads(raw) for name, raw in emitted if name == 'evidence/receipt.json']
                drift = [json.loads(raw) for name, raw in emitted if name == 'evidence/inventory-drift.json']
                if failure == 'inventory':
                    expected_drift = flow.b_inventory_document(input_b); expected_drift['rows'][0]['bytes'] += 1
                    self.assertEqual(drift, [{'status': 'refused', 'reason': 'b-inventory-drift',
                        'source': sha, 'inventory': expected_drift}])
                else: self.assertEqual(drift, [])
                if failure in ('early-input', 'early-finish'):
                    self.assertIs(caught, initial_failure)
                    self.assertEqual(events, ['inputs']); self.assertEqual(calls, []); self.assertEqual(emitted, [])
                    self.assertEqual(len(clocks), 1); self.assertEqual(clocks[0].finishes, 1)
                    self.assertTrue(clocks[0].failed)
                    self.assertEqual(clocks[0].finished, failure == 'early-input')
                    self.assertIsNone(returned)
                    continue
                self.assertEqual(events, ['inputs', 'sdk'])
                self.assertEqual([clock.seconds for clock in clocks], [30, 900, 1200])
                self.assertEqual([clock.finishes for clock in clocks], [1, 1, 0])
                self.assertEqual([call[0] for call in calls[:6]], ['source-head-pre', 'source-clean-pre',
                    'android-public-tool-acquisition', 'android-dependency-jdk-version',
                    'android-dependency-gradle-version', 'android-dependency-locked-task'])
                self.assertEqual(calls[5][1][-3:], ['--dependency-verification', 'strict', ':app:bundleRelease'])
                self.assertFalse(any(arg.startswith(('--write-locks', '--update-locks', '--write-verification-metadata'))
                                     for arg in calls[5][1]))
                self.assertEqual(calls[5][2:], (900, 2 << 20))
                if failure is not None:
                    self.assertIsInstance(caught, flow.Refused)
                    self.assertEqual(str(caught), {'inventory': 'b-inventory-drift', 'inventory-publisher': 'b-inventory-drift',
                        'inventory-clock': 'b-inventory-drift', 'late-lock': 'inert-late-lock-post', 'late-input': 'inert-late-input-post'}[failure])
                    self.assertEqual(receipts, []); self.assertIsNone(returned)
                    self.assertIn('evidence/failed-commands.json', [name for name, raw in emitted])
                else:
                    self.assertIsNone(caught); self.assertIs(returned, clocks[-1]); self.assertFalse(returned.finished)
                    self.assertEqual(counters, {'input': 3, 'lock': 3}); self.assertEqual(len(receipts), 1)
                    self.assertEqual([call[0] for call in calls[-2:]], ['source-head-post', 'source-clean-post'])
                    self.assertEqual(len(calls), 8)
                    receipt_b = receipts[0]
                    self.assertEqual(receipt_b['phase'], 'B')
                    self.assertEqual(receipt_b['status'], 'closed-awaiting-distinct-b-data-review')
                    self.assertEqual(receipt_b['aInputStatement'], flow.b_input_statement(nominated_b))
                    self.assertEqual(receipt_b['aInputOriginals'], {name: list(identity) for name, identity in identities.items()})
                    self.assertEqual(receipt_b['lockOriginals'], json.loads(flow.encoded(lock_b)))
                    self.assertFalse(receipt_b['protectedRegistration']); self.assertFalse(receipt_b['uiQualification'])
                    evidence = dict(emitted)
                    inventory_b = json.loads(evidence['evidence/inventory.json'])
                    self.assertTrue(inventory_b['locksAreReviewedAInputs'])
                    self.assertFalse(inventory_b['locksAreOriginalGradleTaskOutputs'])
                    self.assertEqual(receipt_b['inventorySha256'], flow.digest(evidence['evidence/inventory.json']))
                    self.assertEqual(evidence['evidence/buildscript-gradle.lockfile'], raw_inputs['buildscript-gradle.lockfile'])
                    self.assertEqual(evidence['evidence/app-gradle.lockfile'], raw_inputs['app-gradle.lockfile'])
                    self.assertIs(flow.B_DATA, flow_nomination)

        # Separate synthetic cases: pure A inventory DATA admission, without
        # nominating a run or claiming these synthetic sizes are native evidence.
        import xml.etree.ElementTree as ET
        xml_raw = (ROOT / 'desktop/tools/android_dependency_preparation_data/verification-v1.xml').read_bytes()
        xml_pin = (len(xml_raw), helper.digest(xml_raw))
        xml = ET.fromstring(xml_raw); ns = {'v': 'https://schema.gradle.org/dependency-verification'}
        all_rows = []
        for component in xml.findall('v:components/v:component', ns):
            for artifact in component.findall('v:artifact', ns):
                all_rows.append(dict(component.attrib, artifact=artifact.attrib['name'], bytes=1,
                                     sha256=artifact.find('v:sha256', ns).attrib['value']))
        def inventory_data(rows):
            return {'classification': 'actual-cache-artifacts-not-independent-task-resolution-graph',
                    'locksAreOriginalGradleTaskOutputs': True, 'rows': rows}
        data = inventory_data(all_rows)
        raw = helper.encoded(data)
        self.assertGreater(len(raw), 65536); self.assertLess(len(raw), 1 << 20)
        admitted = helper.admit_a_inventory(raw, xml_raw, xml_pin)
        self.assertEqual(len(admitted), 386)
        self.assertEqual(admitted, helper.admit_a_inventory(helper.encoded(inventory_data(all_rows[::-1])), xml_raw, xml_pin))
        self.assertEqual(admitted, tuple(sorted(tuple(row[k] for k in ('group', 'name', 'version', 'artifact', 'bytes', 'sha256'))
                                              for row in all_rows)))
        minimal = inventory_data([all_rows[0]])
        tiny = helper.encoded(minimal)
        self.assertEqual(helper.admit_a_inventory(tiny + b' ' * ((1 << 20) - len(tiny)), xml_raw, xml_pin),
                         helper.admit_a_inventory(tiny, xml_raw, xml_pin))
        with self.assertRaisesRegex(helper.Refused, '^a-inventory-input-bound$'):
            helper.admit_a_inventory(tiny + b' ' * ((1 << 20) + 1 - len(tiny)), xml_raw, xml_pin)
        for invalid in (b'', None):
            with self.assertRaisesRegex(helper.Refused, '^a-inventory-input-bound$'):
                helper.admit_a_inventory(invalid, xml_raw, xml_pin)
        for changed in (dict(minimal, extra=True), dict(minimal, locksAreOriginalGradleTaskOutputs=False),
                        dict(minimal, classification='independent-resolution-graph')):
            with self.assertRaisesRegex(helper.Refused, '^a-inventory-fields$'):
                helper.admit_a_inventory(helper.encoded(changed), xml_raw, xml_pin)
        for rows in ([], [all_rows[0]] * 1025):
            with self.assertRaisesRegex(helper.Refused, '^a-inventory-row-bound$'):
                helper.admit_a_inventory(helper.encoded(inventory_data(rows)), xml_raw, xml_pin)
        with self.assertRaisesRegex(helper.Refused, '^a-inventory-duplicate-artifact$'):
            helper.admit_a_inventory(helper.encoded(inventory_data([all_rows[0], all_rows[0]])), xml_raw, xml_pin)
        for change, reason in (({'bytes': True}, 'row-types'), ({'bytes': 0}, 'row-types'),
                ({'bytes': (64 << 20) + 1}, 'row-types'), ({'sha256': '0' * 64}, 'unreviewed-artifact'),
                ({'group': 'private.unreviewed'}, 'unreviewed-artifact'), ({'name': []}, 'row-types'),
                ({'extra': 1}, 'row-fields')):
            with self.subTest(inventory_change=change), self.assertRaisesRegex(helper.Refused, '^a-inventory-' + reason + '$'):
                helper.admit_a_inventory(helper.encoded(inventory_data([dict(all_rows[0], **change)])), xml_raw, xml_pin)
        full_budget = [dict(row, bytes=64 << 20) for row in all_rows[:4]]
        self.assertEqual(sum(row[4] for row in helper.admit_a_inventory(helper.encoded(inventory_data(full_budget)), xml_raw, xml_pin)), 256 << 20)
        with self.assertRaisesRegex(helper.Refused, '^a-inventory-byte-bound$'):
            helper.admit_a_inventory(helper.encoded(inventory_data(full_budget + [all_rows[4]])), xml_raw, xml_pin)
        duplicate = tiny.replace(b'"rows":', b'"rows":[],"rows":', 1)
        with self.assertRaisesRegex(normal.Refused, '^duplicate-json-key$'):
            helper.admit_a_inventory(duplicate, xml_raw, xml_pin)
        with self.assertRaisesRegex(helper.Refused, '^a-inventory-nonfinite$'):
            helper.admit_a_inventory(tiny.replace(b'"bytes":1', b'"bytes":NaN'), xml_raw, xml_pin)
        with self.assertRaisesRegex(helper.Refused, '^a-inventory-verification-pin$'):
            helper.admit_a_inventory(tiny, xml_raw + b' ', xml_pin)
        # Even explicitly provided altered XML DATA cannot collapse duplicate rows.
        first = xml.find('v:components/v:component', ns)
        first.append(ET.fromstring(ET.tostring(first.find('v:artifact', ns))))
        duplicate_xml = ET.tostring(xml)
        with self.assertRaisesRegex(helper.Refused, '^a-inventory-xml-artifact$'):
            helper.admit_a_inventory(tiny, duplicate_xml, (len(duplicate_xml), helper.digest(duplicate_xml)))

        # Dormant pure lock DATA only. All coordinates/configurations below
        # are synthetic test inputs, not a nomination of successful A evidence.
        lock_header = (b'# This is a Gradle generated file for dependency locking.\n'
                       b'# Manual edits can break the build and are not advised.\n'
                       b'# This file is expected to be part of source control.\n')
        def lock_data(records):
            return lock_header + ('\n'.join(records) + '\n').encode('utf-8')
        root_rows = ['com.android.tools.build:gradle:8.9.2=classpath',
                     'example.synthetic:shared:1.0-jre=other,classpath',
                     'example.synthetic:shared:2.0-rc1=alternate', 'empty=unusedRoot']
        app_rows = ['example.synthetic:runtime:3.0=releaseRuntimeClasspath,releaseCompileClasspath',
                    'example.synthetic:support:4.0=releaseRuntimeClasspath', 'empty=unusedApp,lintOnly']
        root_raw, app_raw = lock_data(root_rows), lock_data(app_rows)
        original_locks = root_raw, app_raw
        expected_locks = (
            (('alternate', (('example.synthetic', 'shared', '2.0-rc1'),)),
             ('classpath', (('com.android.tools.build', 'gradle', '8.9.2'),
                            ('example.synthetic', 'shared', '1.0-jre'))),
             ('other', (('example.synthetic', 'shared', '1.0-jre'),)), ('unusedRoot', ())),
            (('lintOnly', ()),
             ('releaseCompileClasspath', (('example.synthetic', 'runtime', '3.0'),)),
             ('releaseRuntimeClasspath', (('example.synthetic', 'runtime', '3.0'),
                                         ('example.synthetic', 'support', '4.0'))), ('unusedApp', ())))
        admitted_locks = helper.admit_a_locks(root_raw, app_raw)
        self.assertEqual(admitted_locks, expected_locks)
        self.assertEqual((root_raw, app_raw), original_locks)
        self.assertIs(type(admitted_locks), tuple)
        for file_states in admitted_locks:
            self.assertIs(type(file_states), tuple)
            for state in file_states:
                self.assertIs(type(state), tuple); self.assertIs(type(state[1]), tuple)
                for gav in state[1]: self.assertIs(type(gav), tuple)
        permuted_root = lock_data([root_rows[2], root_rows[1].replace('other,classpath', 'classpath,other'),
                                   root_rows[0], root_rows[3]])
        permuted_app = lock_data([app_rows[1], app_rows[0].replace('releaseRuntimeClasspath,releaseCompileClasspath',
                                      'releaseCompileClasspath,releaseRuntimeClasspath'), 'empty=lintOnly,unusedApp'])
        self.assertEqual(helper.admit_a_locks(permuted_root, permuted_app), expected_locks)
        self.assertEqual(helper.admit_a_locks(root_raw.replace(b'\n', b'\r\n'),
                                             app_raw.replace(b'\n', b'\r\n')), expected_locks)
        self.assertEqual(helper.admit_a_locks(root_raw + b'# retained comment\n\n', app_raw), expected_locks)
        minimal_root = lock_data([root_rows[0], 'empty='])
        empty_app = lock_data(['empty=secondEmpty,firstEmpty'])
        self.assertEqual(helper.admit_a_locks(minimal_root, empty_app),
                         ((('classpath', (('com.android.tools.build', 'gradle', '8.9.2'),)),),
                          (('firstEmpty', ()), ('secondEmpty', ()))))
        padding = (32 << 10) - len(root_raw) - len(app_raw)
        padded_root = root_raw + b'#' + b'x' * (padding - 2) + b'\n'
        self.assertEqual(len(padded_root) + len(app_raw), 32 << 10)
        self.assertEqual(helper.admit_a_locks(padded_root, app_raw), expected_locks)
        with self.assertRaisesRegex(helper.Refused, '^a-locks-input-bound$'):
            helper.admit_a_locks(padded_root + b'x', app_raw)
        for bad in (b'', None, '', bytearray(root_raw), memoryview(root_raw), 1):
            for values in ((bad, app_raw), (root_raw, bad)):
                with self.subTest(lock_type=type(bad).__name__), self.assertRaisesRegex(helper.Refused, '^a-locks-input-bound$'):
                    helper.admit_a_locks(*values)
        malformed = [root_raw.replace(b'# This is', b'# Not this', 1), root_raw + b'\xff',
                     root_raw.replace(b'\n', b'\r', 1), root_raw + b'\x00', root_raw + b'\t',
                     lock_data(['example.synthetic:shared=classpath', 'empty=']),
                     lock_data([':shared:1=classpath', 'empty=']),
                     lock_data(['example.synthetic:shared:1:classifier=classpath', 'empty=']),
                     lock_data([root_rows[0] + '=extra', 'empty=']),
                     lock_data([root_rows[0] + ',', 'empty=']),
                     lock_data([root_rows[0].replace('=classpath', '='), 'empty=']),
                     lock_data([root_rows[0].replace('=classpath', '=class path'), 'empty=']),
                     lock_data([root_rows[0].replace('=classpath', '=clásspath'), 'empty=']),
                     lock_data([root_rows[0]]), lock_data([root_rows[0], 'empty=', 'empty=other']),
                     lock_data(['empty=other', root_rows[0]]),
                     lock_data([root_rows[0], root_rows[0], 'empty=']),
                     lock_data([root_rows[0], root_rows[0].replace('=classpath', '=other'), 'empty=']),
                     lock_data([root_rows[0] + ',classpath', 'empty=']),
                     lock_data([root_rows[0], 'empty=other,other']),
                     lock_data([root_rows[0], 'empty=,other']),
                     lock_data([root_rows[0], 'empty=classpath']),
                     lock_data([root_rows[0], 'com.android.tools.build:gradle:8.9.1=classpath', 'empty='])]
        for version in ('1.+', '[1.0,2.0)', '(1.0,2.0]', 'latest.release', 'latest.integration', '1.0-SNAPSHOT'):
            malformed.append(lock_data([root_rows[0], 'example.synthetic:shared:' + version + '=other', 'empty=']))
        for bad in malformed:
            with self.subTest(lock_sha256=helper.digest(bad)), self.assertRaises(helper.Refused) as refused:
                helper.admit_a_locks(bad, app_raw)
            self.assertTrue(str(refused.exception).startswith('a-locks-'))
        for bad in (lock_data(['empty=']), lock_data(['empty=other', 'example.synthetic:x:1=release'])):
            with self.assertRaises(helper.Refused): helper.admit_a_locks(root_raw, bad)
        missing_agp = [lock_data(['example.synthetic:other:1=classpath', 'empty=']),
                       lock_data([root_rows[0].replace('8.9.2', '8.9.1'), 'empty=']),
                       lock_data([root_rows[0].replace('=classpath', '=other'), 'empty=']),
                       lock_data([root_rows[0].replace('=classpath', '=Classpath'), 'empty=']),
                       lock_data(['empty=classpath'])]
        for bad in missing_agp:
            with self.assertRaisesRegex(helper.Refused, '^a-locks-required-root-agp-classpath$'):
                helper.admit_a_locks(bad, lock_data([root_rows[0], 'empty=']))

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
            self.assertEqual(emitted[0][1]['role'], 'android-dependency-locked-task')
            self.assertEqual(emitted[0][1]['originalReturncode'], 1)
            helper.publish_preparation = interrupted
            helper.publish_gradle_failure(work, result, project_raw, verification, Clock())
        finally: helper.gradle_failure_projection, helper.publish_preparation = saved_projection, saved_publish
