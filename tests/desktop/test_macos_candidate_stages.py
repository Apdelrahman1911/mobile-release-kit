"""Checkpoint/rerun correspondence. All packages and native ports are inert."""
import copy
import importlib.util
import json
import os
import re
import gzip
import struct
import zlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.desktop.test_macos_prepared_package import P, fixture, real_modules
from tests.desktop import test_macos_identity_current_runtime as D
from tests.desktop import test_macos_aqua_qualification as A

ROOT = Path(__file__).resolve().parents[2]


class ServiceLogDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('_test_service_log',
            ROOT / 'desktop/tools/macos_tool_service_diagnostic.py')
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_only_finite_own_codes_paths_and_words_leave_the_parser(self):
        m = self.module
        rows = [{'subsystem': m.SUBSYSTEMS[0], 'eventMessage': m.IDS[1]
            + ' failed to find plist "' + m.PATHS['outer-plist']
            + '" Error Domain=SMAppServiceErrorDomain Code=8 CANARY_PRIVATE_DESCRIPTION'},
            {'subsystem': m.SUBSYSTEMS[0], 'eventMessage': m.IDS[0]
             + '.foreign Error Domain=NSPOSIXErrorDomain Code=13 CANARY_FOREIGN'},
            {'processImagePath': m.SMD_PATHS[1], 'eventMessage': m.IDS[1]
             + ' signature Error Domain=NSOSStatusErrorDomain Code=-67050 CANARY_OTHER'}]
        result = m.project(json.dumps(rows).encode())
        self.assertEqual(result['matchingEvents'], 2)
        self.assertEqual(result['details'][0]['pathsMentioned'], ['outer-plist'])
        self.assertEqual(result['details'][0]['errorCodes'], [{'domain': 'smappservice', 'code': 8}])
        self.assertEqual(result['details'][1]['errorCodes'], [{'domain': 'osstatus', 'code': -67050}])
        encoded = json.dumps(result)
        self.assertNotIn('CANARY', encoded)
        self.assertNotIn('/Library/', encoded)
        self.assertNotIn('foreign', encoded)
        self.assertFalse(m.project(b'[]')['matchingEvents'])

    def test_malformed_or_excessive_data_is_not_a_diagnostic(self):
        m = self.module
        for raw in (b'{"a":1,"a":2}', b'[NaN]', b'[]' + b'x', b' ' * (m.LIMIT + 1),
                    json.dumps([{'eventMessage': 'x' * 8193}]).encode(),
                    json.dumps([{'eventMessage': ''}] * 513).encode()):
            with self.subTest(raw=raw[:30]), self.assertRaises((ValueError, UnicodeError)):
                m.project(raw)

    def test_diagnostic_never_promotes_an_empty_or_failed_original_to_service_success(self):
        m = self.module
        for code, body, state in ((0, b'[]', 'empty'), (1, b'CANARY', 'call-failed'),
                                  (0, b'CANARY', 'unparseable')):
            def owned(argv, **kwargs):
                self.assertEqual(kwargs['output_limit'], m.LIMIT)
                self.assertEqual(kwargs['timeout'], 25)
                self.assertEqual(argv[:2], ['/usr/bin/log', 'show'])
                return subprocess.CompletedProcess(argv, code, body, b'')
            result = m.collect(owned, {}, ROOT)
            self.assertEqual(result['state'], state)
            self.assertTrue(result['originalCallReturned'])
            self.assertFalse(result['serviceQualified'])
            self.assertNotIn('CANARY', json.dumps(result))
        def unknown(*args, **kwargs):
            raise RuntimeError('CANARY unknown original')
        result = m.collect(unknown, {}, ROOT)
        self.assertEqual(result['state'], 'call-unknown')
        self.assertFalse(result['originalCallReturned'])
        self.assertFalse(result['serviceQualified'])
        self.assertNotIn('CANARY', json.dumps(result))

    def btm(self):
        m = self.module
        return (' Records for UID -2 : FFFFEEEE-DDDD-CCCC-BBBB-AAAAFFFFFFFE\n'
            ' #1:\n'
            '                 Name: CANARY_PRIVATE_NAME\n'
            '                 Type: daemon (0x10)\n'
            '          Disposition: [disabled, disallowed, not notified] (pending authorization) (0x10)\n'
            '           Identifier: 16.' + m.IDS[1] + '\n'
            '                  URL: Contents/Library/LaunchDaemons/' + m.IDS[1] + '.plist\n'
            '      Executable Path: Contents/Helpers/mrk-android-register\n'
            '    Parent Identifier: 2.' + m.IDS[0] + '\n'
            ' Records for UID 501 : FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F5\n'
            ' #1:\n'
            '           Identifier: 16.' + m.IDS[1] + '.foreign\n'
            '                  URL: /CANARY_PRIVATE_PATH\n').encode()

    def test_btm_projects_exact_daemon_records_without_claiming_live_status(self):
        m = self.module
        result = m.background_tasks(self.btm(), 501)
        self.assertEqual(result['matchingRecords'], 1)
        self.assertEqual(result['records'], [dict(scope='system', type='daemon',
            disposition=['disabled', 'disallowed', 'not-notified'], pendingAuthorization=True,
            dispositionBits=16, plist='payload-relative-match', executable='payload-relative-match',
            parent='payload-identifier-match')])
        self.assertFalse(result['serviceQualified'])
        self.assertTrue(result['recordsMayRemainAfterUnregister'])
        self.assertNotIn('CANARY', json.dumps(result))
        self.assertNotIn(m.IDS[1], json.dumps(result))
        self.assertEqual(m.background_tasks(self.btm().replace(m.IDS[1].encode(), b'foreign'), 501)['state'], 'empty')

    def test_btm_malformed_matched_records_are_refused(self):
        m = self.module
        body = self.btm()
        own = ('           Identifier: 16.' + m.IDS[1] + '\n').encode()
        for raw in (b'CANARY', body.replace(own, own + own), body.replace(b'daemon (0x10)', b'app (0x2)'),
                body.replace(b'[disabled, disallowed, not notified]', b'[unknown]'),
                body.replace(b'    Parent Identifier:', b'    Missing Identifier:'),
                b' ' * (m.LIMIT + 1), body + b'\xff'):
            with self.subTest(raw=raw[:30]), self.assertRaises((ValueError, UnicodeError)):
                m.background_tasks(raw, 501)

    def test_btm_original_errors_cannot_grant_service_readiness(self):
        m = self.module
        for code, body, state in ((0, self.btm(), 'observed'), (1, b'CANARY', 'call-failed'),
                                 (0, b'CANARY', 'unparseable')):
            def owned(argv, **kwargs):
                self.assertEqual(argv, ['/usr/bin/sfltool', 'dumpbtm'])
                self.assertEqual(kwargs['timeout'], 20)
                self.assertEqual(kwargs['output_limit'], m.LIMIT)
                return subprocess.CompletedProcess(argv, code, body, b'')
            result = m.collect_background_tasks(owned, {}, ROOT, 501)
            self.assertEqual(result['state'], state)
            self.assertTrue(result['originalCallReturned'])
            self.assertFalse(result['serviceQualified'])
            self.assertNotIn('CANARY', json.dumps(result))
        def unknown(*args, **kwargs):
            raise RuntimeError('CANARY unknown original')
        result = m.collect_background_tasks(unknown, {}, ROOT, 501)
        self.assertEqual(result['state'], 'call-unknown')
        self.assertFalse(result['originalCallReturned'])
        self.assertFalse(result['serviceQualified'])


def native_fixture(scope='git-native'):
    values, manifest, service, consumer = fixture()
    manifest.update(schemaVersion=2, packageRole='installed-shell-observation')
    manifest['observerBuild'] = dict(appBinarySha256BeforeSigning='a'*64, entryBinarySha256BeforeSigning='b'*64)
    del manifest['normalBuild']
    manifest['origin'].update(nativeScope=scope, hostProfile=P.NATIVE_HOSTS[scope])
    consumer.update(nativeScope=scope, hostProfile=P.NATIVE_HOSTS[scope])
    service['job'].update(name=P.NATIVE_JOB_NAMES[scope], status='completed', conclusion='success',
        steps=[dict(name=n, number=i+1, status='completed', conclusion='success') for i,n in enumerate(P.NATIVE_PRODUCER_STEPS)])
    service['artifact']['name'] = P.artifact_name(manifest['origin'])
    values['PREPARED.json'] = P.canonical(manifest)
    return values, manifest, service, consumer


class CandidateCheckpointTests(unittest.TestCase):
    def test_dispatch_originals_distinguish_same_source_from_changed_harness(self):
        _, stage, helper = real_modules()
        for scope in P.NATIVE_HOSTS:
            for changed, comparison_present, product_change, expected in (
                (False, False, False, None),
                (False, True, False, 'prepared-service-original-roster'),
                (True, True, False, None),
                (True, False, False, 'prepared-service-original-roster'),
                (True, True, True, 'prepared-harness-files'),
            ):
                with self.subTest(scope=scope, changed=changed, comparison=comparison_present,
                                  product_change=product_change), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    checkout, work = root / 'source', root / 'work'
                    checkout.mkdir(); work.mkdir(mode=0o700)
                    (checkout / '.git').mkdir()
                    values, manifest, service, consumer = native_fixture(scope)
                    if changed:
                        consumer.update(source='6' * 40, tree='7' * 40)
                    head = checkout / '.git/HEAD'
                    head.write_text(consumer['source'] + '\n')
                    # Match a real checkout's source-file contract even when
                    # the CI parent creates disposable files under umask077.
                    head.chmod(0o644)
                    service_root = work / 'prepared-service'; service_root.mkdir()
                    records = dict(service, commit=dict(sha=manifest['origin']['source'],
                        tree={'sha': manifest['origin']['tree']}))
                    if comparison_present:
                        base = dict(sha=manifest['origin']['source'],
                                    commit={'tree': {'sha': manifest['origin']['tree']}})
                        records['compatibility'] = dict(status='ahead', ahead_by=1, behind_by=0,
                            total_commits=1, base_commit=base, merge_base_commit=base,
                            commits=[dict(sha=consumer['source'], commit={'tree': {'sha': consumer['tree']}})],
                            files=[dict(filename='desktop/src-tauri/src/main.rs' if product_change else
                                'desktop/tools/macos_prepared_package.py', status='modified')])
                    for name, value in records.items():
                        (service_root / (name + '.json')).write_bytes(P.canonical(value))
                    (service_root / 'metadata.status').write_bytes(b'0\n')
                    inputs = work / 'prepared-input'; inputs.mkdir()
                    for name, body in values.items():
                        (inputs / name).write_bytes(body)
                    env = dict(GITHUB_SHA=consumer['source'], GITHUB_WORKFLOW_SHA=consumer['source'],
                        GITHUB_RUN_ID='41', GITHUB_RUN_ATTEMPT='2', MRK_MACOS_PREPARED_RESUME='true',
                        GITHUB_WORKFLOW_REF=P.REPOSITORY + '/' + P.WORKFLOW + '@refs/heads/' + P.BRANCH,
                        MRK_MACOS_PACKAGE_ROLE='installed-shell-observation')
                    native = mock.Mock(side_effect=AssertionError('native execution is outside this DATA fixture'))
                    op = helper.Operation(SimpleNamespace(run_owned=native), checkout, work,
                                          'package-install', env, stage, target=P.TARGETS[0])
                    # Original opens, reads, hashes, roster checks, provenance and closes are real.
                    # Only OS resource admission is inert; this fixture cannot install or sign.
                    with mock.patch.object(P, 'ResourceGuard'):
                        if expected:
                            with self.assertRaisesRegex(ValueError, expected):
                                P.acquire_checkpoint(op, consumer)
                        else:
                            actual, binding = P.acquire_checkpoint(op, consumer)
                            self.assertEqual(actual, values)
                            self.assertEqual(binding.same_source, not changed)
                            self.assertTrue(binding.native_compatible)
                            self.assertEqual(binding.origin, manifest['origin'])
                    native.assert_not_called()
                    self.assertTrue(op.receipt['originalClosesKnown'] and op.receipt['targetRetired'])
                    self.assertFalse(op.receipt['passed'])
                    self.assertTrue(all(row['closed'] and row['fd'] is None for row in op.entries))

    def test_dispatch_fixture_admits_originals_under_private_creation_mask(self):
        previous = os.umask(0o077)
        try:
            self.test_dispatch_originals_distinguish_same_source_from_changed_harness()
        finally:
            os.umask(previous)

    def test_cold_producer_budget_does_not_extend_native_calls_or_ordinary_installs(self):
        from tests.desktop.test_macos_installed_staging import ANDROID_HELPER as H
        values, _, service, consumer = native_fixture('tool-setup')
        prepared = P.admit_data(values, service, consumer)
        output = (b'\nrunning 1 test\ntest emitter::tests::fixed_cli_and_original_state_data_refuse_ambient_or_partial_routes ... ok\n\n'
                  b'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n\n')
        class Compiler(H.Operation):
            def __init__(self):
                self.phase='package-install';self.prepared_binding=prepared
                self.target=P.TARGETS[0];self.checkout=Path('/inert/source');self.work=Path('/inert/work')
                self.target_name='compiler';self.image_package_version='0.2.0'
                self.package_endpoint=1410_000_000_000;self.now=0;self.calls=[]
            def package_clock(self):return self.now
            def package_call(self,role,argv,**options):
                self.calls.append((role,options['timeout']))
                self.now+=(600 if role=='producer-tests' else 50)*1_000_000_000
                return subprocess.CompletedProcess(argv,0,output if role=='producer-tests' else b'INERT graph',b'')
        compiler=Compiler()
        with mock.patch.object(H,'producer_artifact',return_value=Path('/inert/program')):
            self.assertEqual(compiler.package_producer_compile({}),Path('/inert/program'))
        self.assertEqual(compiler.calls,[('producer-tests',897),('producer-build',297)])
        compiler.prepared_binding=None
        self.assertEqual(compiler.package_compiler_seconds(),480)
        compiler.prepared_binding=prepared;compiler.phase='package-remove'
        self.assertEqual(compiler.package_compiler_seconds(),480)
        for role in ('installer','producer-emitter','distribution-sign','distribution-detach'):
            with self.subTest(role=role),self.assertRaises(H.Refused):
                H.package_timeout_data(0,1410_000_000_000,900,phase='package-install',role=role,prepared_compiler=True)
        for extended in (False,True):
            with self.assertRaises(H.Refused):
                H.package_timeout_data(0,1410_000_000_000,901,phase='package-install',role='producer-tests',prepared_compiler=extended)
        with self.assertRaises(H.Refused):
            H.package_timeout_data(898_000_000_000,900_000_000_000,900,
                phase='package-install',role='producer-build',prepared_compiler=True)

    def test_streaming_census_enforces_real_expansion_and_complete_single_stream(self):
        body=b'inert payload\n'*100000
        packed=gzip.compress(body,mtime=0)
        clock=mock.Mock()
        self.assertEqual(P.gzip_expansion_bytes(memoryview(packed),check=clock),len(body))
        clock.assert_called()
        for wrong,limit in ((packed,len(body)-1),(packed[:-1],len(body)),(packed+packed,len(body)*2)):
            with self.subTest(size=len(wrong)),self.assertRaises(ValueError):
                P.gzip_expansion_bytes(memoryview(wrong),limit=limit)

    def test_small_xar_index_chooses_actual_cpio_expansion_before_full_allocation(self):
        payload=gzip.compress(b'INERT scripts'*100000,mtime=0)
        def archive(size):
            toc=('<xar><toc><file><name>PackageInfo</name><type>file</type></file>'
                 '<file><name>Scripts</name><type>file</type><data>'
                 f'<offset>0</offset><length>{len(payload)}</length><size>{size}</size>'
                 '<encoding style="application/octet-stream"/></data></file></toc></xar>').encode()
            packed=zlib.compress(toc)
            return struct.pack('>IHHQQI',0x78617221,28,1,len(packed),len(toc),0)+packed+payload
        stage=SimpleNamespace(inflate=lambda body,limit:zlib.decompress(body))
        measured=P.original_expansion_bytes(stage,archive(len(payload)))
        self.assertEqual(measured,1300000)
        with self.assertRaisesRegex(ValueError,'prepared-expansion-index'):
            P.original_expansion_bytes(stage,archive(len(payload)+1))
        actual=P.quote_data(147511836,147514243,503000000,12*P.MIB)
        maximum=P.quote_data(147511836,147514243,P.PACKAGE_LIMIT,12*P.MIB)
        available=3014819840
        self.assertLess(actual['memoryBytes'],available)
        self.assertGreater(maximum['memoryBytes'],available)

    def test_helper_continuation_requires_complete_ancestor_comparison_and_no_product_changes(self):
        values, manifest, service, consumer = native_fixture()
        consumer.update(source='6'*40, tree='7'*40)
        origin=manifest['origin']
        base=dict(sha=origin['source'], commit={'tree':{'sha':origin['tree']}})
        comparison=dict(status='ahead', ahead_by=1, behind_by=0, total_commits=1,
            base_commit=base, merge_base_commit=base,
            commits=[dict(sha=consumer['source'],commit={'tree':{'sha':consumer['tree']}})],
            files=[dict(filename='desktop/tools/macos_prepared_package.py',status='modified')])
        bound=P.admit_data(values,dict(service,compatibility=comparison),consumer)
        self.assertFalse(bound.same_source)
        self.assertTrue(bound.native_compatible)
        self.assertEqual(bound.source,origin['source'])
        for name in ('desktop/tools/macos_android_helper_package.py',
                     'tests/desktop/test_macos_distribution_detach.py'):
            current=copy.deepcopy(comparison);current['files'][0]['filename']=name
            with self.subTest(harness=name):
                continued=P.admit_data(values,dict(service,compatibility=current),consumer)
                self.assertTrue(continued.native_compatible)
                self.assertEqual(continued.source,origin['source'])
        for name in ('desktop/src-tauri/src/main.rs','desktop/native/macos-installed-native/src/native.m',
                     'desktop/packaging/macos-android-service-signing.profile','desktop/tools/stage_macos_installed.py',
                     'mobile_release/core.py'):
            wrong=copy.deepcopy(comparison);wrong['files'][0]['filename']=name
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'prepared-harness-files'):
                P.admit_data(values,dict(service,compatibility=wrong),consumer)
        changes=[('status','diverged'),('behind_by',1),('total_commits',2),('files',[]),
                 ('files',comparison['files']*300),('merge_base_commit',dict(sha='9'*40)),
                 ('commits',[dict(sha='9'*40,commit={'tree':{'sha':consumer['tree']}})])]
        for key,value in changes:
            wrong=copy.deepcopy(comparison);wrong[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                P.admit_data(values,dict(service,compatibility=wrong),consumer)

    def test_failure_diagnostics_never_echo_unrecognized_exception_text(self):
        for error in (ValueError('private token'),RuntimeError('prepared-resource-insufficient'),
                      ValueError('prepared-resource-insufficient','private token')):
            data=P.failure_data(error,'hydrate',None)
            self.assertEqual(data['reason'],'unclassified')
            self.assertNotIn('private token',json.dumps(data))
        self.assertEqual(P.failure_data(ValueError('prepared-resource-insufficient'),'hydrate',None)['reason'],
                         'prepared-resource-insufficient')

    def test_preparation_diagnostic_maps_same_exception_without_private_text(self):
        namespace = {}
        exec(compile("def fail():\n raise PermissionError(13, 'CANARY_PRIVATE_PATH')\n",
                     str(A.M.__file__), 'exec'), namespace)
        fixtures = SimpleNamespace(stage='prepare', inflight=False, last_returned=False)
        try:
            namespace['fail']()
        except PermissionError as caught:
            result = A.M._preparation_exception_diagnostic(caught, fixtures)
            self.assertEqual(result['exceptionCategory'], 'os-error')
            self.assertEqual(result['errno'], 13)
            self.assertEqual(result['sites'], [dict(role='aqua-fixture', line=2)])
            self.assertTrue(result['tracebackComplete'])
            self.assertNotIn('CANARY', json.dumps(result))
            self.assertNotIn(str(ROOT), json.dumps(result))
            fixtures.inflight = True
            self.assertIsNone(A.M._preparation_exception_diagnostic(caught, fixtures))
        class PrivateError(Exception):
            def __str__(self): raise AssertionError('private exception must not be formatted')
        fixtures.inflight = False
        self.assertEqual(A.M._preparation_exception_diagnostic(PrivateError(), fixtures)['exceptionCategory'], 'unknown')

    def test_preparation_diagnostic_bounds_traceback_and_has_no_success_authority(self):
        namespace = {}
        path = ROOT / 'desktop/tools/macos_identity_current_runtime.py'
        exec(compile("def fail(n):\n if n: return fail(n-1)\n raise KeyError('CANARY_PRIVATE_KEY')\n",
                     str(path), 'exec'), namespace)
        fixtures = SimpleNamespace(stage='prepare', inflight=False, last_returned=False)
        try:
            namespace['fail'](40)
        except KeyError as caught:
            result = A.M._preparation_exception_diagnostic(caught, fixtures)
            self.assertEqual(result['tracebackLinksSeen'], 32)
            self.assertEqual(len(result['sites']), 8)
            self.assertFalse(result['tracebackComplete'])
            self.assertTrue(result['sitesTruncated'])
            self.assertNotIn('CANARY', json.dumps(result))
            self.assertFalse(set(result) & {'passed', 'originalCallReturned', 'productReady'})
            fixtures.last_returned = True
            self.assertIsNone(A.M._preparation_exception_diagnostic(caught, fixtures))

    def test_native_saved_package_keeps_build_attempt_and_current_consumer_separate(self):
        for scope in P.NATIVE_HOSTS:
            values, manifest, service, consumer = native_fixture(scope)
            bound = P.admit_data(values, service, consumer)
            self.assertEqual(bound.origin['runAttempt'], '1')
            self.assertEqual(bound.consumer['runAttempt'], '2')
            self.assertFalse(bound.manifest['installed'])
            self.assertFalse(bound.manifest['productReady'])
            self.assertEqual(bound.origin['hostProfile'], P.NATIVE_HOSTS[scope])

    def test_failed_job_rerun_selects_original_successful_build_not_new_test_attempt(self):
        for scope in P.NATIVE_HOSTS:
            _, manifest, service, _ = native_fixture(scope)
            old = service['job']
            failed = dict(old, id=90, run_attempt=2, name='Test saved candidate (git-local)', conclusion='failure')
            rows = P.canonical(dict(total_count=2, jobs=[failed, old]))
            selected = P.selected_job_data(rows, '1'*40, '41', P.TARGETS[0], completed=True, native_scope=scope)
            self.assertEqual(selected['id'], 42)
            self.assertEqual(selected['run_attempt'], 1)
            artifacts = P.canonical(dict(total_count=1, artifacts=[service['artifact']]))
            self.assertEqual(P.selected_artifact_data(artifacts, manifest['origin'])['id'], 43)

    def test_native_wrong_host_scope_source_tree_and_role_refuse(self):
        values, manifest, service, consumer = native_fixture()
        for key, wrong in (('nativeScope','tool-setup'),('hostProfile','macos-26'),('source','6'*40),('tree','7'*40)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                P.admit_data(values, service, dict(consumer, **{key:wrong}))
        for scope in (None, [], {}, 17, 'project-identity-native'):
            wrong=copy.deepcopy(manifest);wrong['origin']['nativeScope']=scope
            with self.subTest(scope=scope), self.assertRaises(ValueError):P.manifest_data(wrong)
        for key, wrong in (('schemaVersion',1),('packageRole','ordinary-image'),('installed',True),('productReady',True)):
            with self.subTest(key=key), self.assertRaises(ValueError):P.manifest_data(dict(manifest, **{key:wrong}))

    def test_native_missing_corrupt_expired_and_unclosed_outputs_refuse(self):
        values, manifest, service, consumer = native_fixture()
        for name in values:
            missing=dict(values);missing.pop(name)
            with self.subTest(missing=name), self.assertRaises(ValueError):P.admit_data(missing,service,consumer)
            wrong=dict(values);wrong[name]+=b'corrupt'
            with self.subTest(changed=name), self.assertRaises(ValueError):P.admit_data(wrong,service,consumer)
        for key, wrong in (('expired',True),('size_in_bytes',P.ARTIFACT_LIMIT+1),('digest','sha256:'+'0'*64)):
            changed=copy.deepcopy(service);changed['artifact'][key]=wrong
            with self.subTest(key=key), self.assertRaises(ValueError):P.admit_data(values,changed,consumer)
        for i in range(len(P.NATIVE_PRODUCER_STEPS)):
            for result in ('failure','cancelled','skipped',None):
                changed=copy.deepcopy(service);changed['job']['steps'][i]['conclusion']=result
                with self.subTest(step=i,result=result),self.assertRaises(ValueError):P.admit_data(values,changed,consumer)

    def test_multiple_completed_build_attempts_are_ambiguous_never_latest(self):
        _,_,service,_=native_fixture()
        old=service['job'];other=dict(old,id=99,run_attempt=3)
        with self.assertRaisesRegex(ValueError,'prepared-one-target-job'):
            P.selected_job_data(P.canonical(dict(total_count=2,jobs=[old,other])), '1'*40,'41',P.TARGETS[0],
                                completed=True,native_scope='git-native')

    def test_github_copied_success_job_is_not_a_second_build(self):
        _,manifest,service,_=native_fixture()
        old=service['job'];copied=dict(old,id=99,run_attempt=2)
        jobs=P.canonical(dict(total_count=2,jobs=[old,copied]))
        artifacts=P.canonical(dict(total_count=1,artifacts=[service['artifact']]))
        selected=P.selected_job_data(jobs,'1'*40,'41',P.TARGETS[0],completed=True,
                                    native_scope='git-native',artifacts=artifacts)
        self.assertEqual(selected['id'],old['id'])
        second=dict(service['artifact'],id=100,name=P.artifact_name(dict(manifest['origin'],runAttempt='2')))
        with self.assertRaisesRegex(ValueError,'prepared-one-target-job'):
            P.selected_job_data(jobs,'1'*40,'41',P.TARGETS[0],completed=True,native_scope='git-native',
                artifacts=P.canonical(dict(total_count=2,artifacts=[service['artifact'],second])))

    def test_native_role_cannot_use_ordinary_preview_or_same_named_foreign_job(self):
        values, manifest, service, consumer = native_fixture()
        changed=copy.deepcopy(service);changed['job']['name']='normal-installed-'+P.TARGETS[0]
        with self.assertRaises(ValueError):P.admit_data(values,changed,consumer)
        ordinary=fixture()[3]
        with self.assertRaises(ValueError):P.admit_data(values,service,ordinary)
        for key in ('normalBuild','observerBuild'):
            wrong=copy.deepcopy(manifest);wrong[key]={'appBinarySha256BeforeSigning':'0'*64}
            with self.assertRaises(ValueError):P.manifest_data(wrong)

    def test_native_original_compiler_and_entry_hashes_must_match_before_export(self):
        from tests.desktop import test_macos_installed_staging as T
        _, manifest, _, _ = native_fixture()
        origin=manifest['origin'];work=Path('/inert/checkpoint')
        binary=work/'cargo-target'/P.TARGETS[0]/'debug/deps/installed_shell_observation-123abc'
        messages=b'INERT parsed at compiler port';image=b'INERT compiled observer';entry=b'INERT entry'
        compiled={'binarySha256':P.sha(image)}
        app=dict(packageRole='installed-shell-observation',observerCargoArtifact=compiled,
                 appBinarySha256BeforeSigning=P.sha(image),entryBinarySha256BeforeSigning=P.sha(entry))
        bodies={'observer-build.status':b'0\n','observer-build.jsonl':messages,str(binary.relative_to(work)):image,
                'mrk-macos-entry':entry,'app-result.json':P.canonical(app),
                'source-inventory.json':P.canonical(dict(source=origin['source'],tree=origin['tree'])),
                'source-binding.json':P.canonical(dict(source=origin['source'],tree=origin['tree'],workflowSource=origin['source'],
                    runId=origin['runId'],runAttempt=origin['runAttempt'],scope='current-macos-candidate',
                    instrumented=True,packageRole='installed-shell-observation'))}
        parser=mock.Mock(return_value=compiled)
        op=SimpleNamespace(work=work,target=P.TARGETS[0],work_entry='',package_outputs=[],
            environment={'MRK_MACOS_OBSERVER_BINARY':str(binary)},
            descend=lambda p,parts:str(Path(p).joinpath(*parts)) if parts else p,
            original=lambda parent,name,*args:str(Path(parent)/name),read=lambda name:bodies[name],
            stager=SimpleNamespace(observer_cargo_artifact=parser,entry_macho=mock.Mock()))
        result=P.original_build_facts(op,origin,package_version='0.2.0')
        self.assertEqual(result,manifest['observerBuild'] | {'appBinarySha256BeforeSigning':P.sha(image),'entryBinarySha256BeforeSigning':P.sha(entry)})
        self.assertEqual(parser.call_args.kwargs,dict(target=P.TARGETS[0],package_version='0.2.0'))
        for key in ('appBinarySha256BeforeSigning','entryBinarySha256BeforeSigning'):
            bodies['app-result.json']=P.canonical(dict(app,**{key:'f'*64}))
            with self.assertRaisesRegex(ValueError,'prepared-observer-originals'):
                P.original_build_facts(op,origin,package_version='0.2.0')

    def test_prepared_driver_uses_the_same_owner_once_and_preserves_close_failure(self):
        values, _, service, consumer = native_fixture('tool-setup')
        prepared = P.admit_data(values, service, consumer)
        owner = SimpleNamespace(run_owned=object())
        for close_fails in (False, True):
            fixtures = SimpleNamespace(inflight=False, prepare=mock.Mock(),
                close=mock.Mock(side_effect=RuntimeError('INERT close failure') if close_fails else None))
            records=[]
            def cases(binding, actual, run_owned, uid, username, emit, **options):
                self.assertIs(actual,fixtures)
                self.assertIs(run_owned,owner.run_owned)
                emit({'case':A.M.selected_cases(D.M.CLI_SCOPE)[0]})
                return ()
            with mock.patch.object(A.M,'Fixtures',return_value=fixtures), \
                 mock.patch.object(A.M,'load_owner',side_effect=AssertionError('owner loaded twice')), \
                 mock.patch.object(A.M,'run_cases',side_effect=cases), \
                 mock.patch.object(A.M,'emit_record',side_effect=lambda record,stream:records.append(record)), \
                 mock.patch.object(A.M,'diagnostic',return_value={'inertFailure':True}), \
                 mock.patch.object(D.M,'_current'), \
                 mock.patch.object(D.M,'_admit_prepared_runtime',return_value={'inertOnly':True}):
                status=D.M._run(A.M,A.BINDING,501,20,'runner',Path('/inert'),
                    {'MRK_MACOS_NATIVE_SCOPE':'tool-setup'},scope=D.M.CLI_SCOPE,
                    prepared=prepared,prepared_owner=owner)
            self.assertEqual(status,1 if close_fails else 0)
            fixtures.close.assert_called_once()
            if close_fails:self.assertNotIn('allOriginalCallsReturned',records[-1])
            else:self.assertEqual(records[-1]['runtimeMode'],'prepared-package')

    def test_fresh_install_parser_checks_current_attempt_and_keeps_original_closure_gates(self):
        with A.shipping_gate_stager_data() as stage:
            binding=A.BINDING
            selection,env,observed,anchors=A.shipping_gate_installation_data(stage,binding)
            receipt=json.loads(anchors['android-helper-package-install.json'])
            receipt['workflow']=D.M.WORKFLOW
            anchors['android-helper-package-install.json']=stage.canonical(receipt)
            def check(rows=anchors):
                return A.M._gate_installation(stage.canonical(observed),b'0\n',binding,env,stage,selection,rows,
                                              workflow=D.M.WORKFLOW)
            self.assertEqual(check(),observed)
            for key,wrong in (('runAttempt','999'),('originalClosesKnown',False),('passed',False)):
                changed=dict(anchors);changed['android-helper-package-install.json']=stage.canonical(dict(receipt,**{key:wrong}))
                with self.subTest(key=key),self.assertRaises(A.M.Refused):check(changed)
            for key in ('returned','capturesSettled'):
                changed=copy.deepcopy(receipt);changed['originalCalls'][0][key]=False
                with self.subTest(key=key),self.assertRaises(A.M.Refused):
                    check(dict(anchors,**{'android-helper-package-install.json':stage.canonical(changed)}))

    def test_fresh_install_separates_application_source_from_current_harness_receipt(self):
        with A.shipping_gate_stager_data() as stage:
            old=A.BINDING
            selection,env,observed,anchors=A.shipping_gate_installation_data(stage,old)
            current=A.M.Binding('6'*40,'555','2',old.target).checked()
            receipt=json.loads(anchors['android-helper-package-install.json'])
            receipt.update(source=current.source,workflowSource=current.source,runId=current.run,
                           runAttempt=current.attempt,workflow=D.M.WORKFLOW)
            anchors['android-helper-package-install.json']=stage.canonical(receipt)
            def check(source):
                return A.M._gate_installation(stage.canonical(observed),b'0\n',current,env,stage,selection,anchors,
                    workflow=D.M.WORKFLOW,application_source=source)
            self.assertEqual(check(old.source),observed)
            for wrong in (current.source,'0'*40,None):
                with self.subTest(source=wrong),self.assertRaises(A.M.Refused):check(wrong)

    def test_real_owner_log_diagnostics_do_not_replace_original_call_gates(self):
        from desktop.tools import macos_android_helper_package as helper
        with A.shipping_gate_stager_data() as stage:
            binding=A.BINDING
            selection,env,observed,anchors=A.shipping_gate_installation_data(stage,binding)
            original=json.loads(anchors['android-helper-package-install.json'])
            original['workflow']=D.M.WORKFLOW
            receipt=copy.deepcopy(original)
            for call in receipt['originalCalls']:
                if call['role'] in ('installer-log-cursor','installer-log-capture'):
                    call['installerLog']=helper.installer_log_diagnostic_data(dict(
                        state='unknown',reason='log-no-project-lines',selection='not-created'))
            def check(value):
                rows=dict(anchors,**{'android-helper-package-install.json':stage.canonical(value)})
                return A.M._gate_installation(stage.canonical(observed),b'0\n',binding,env,stage,selection,rows,
                                              workflow=D.M.WORKFLOW)
            self.assertEqual(check(receipt),observed)
            index=next(i for i,c in enumerate(receipt['originalCalls']) if 'installerLog' in c)
            for key,value in (('returned',False),('capturesSettled',False),('returncode',2),
                              ('unexpected','no'),('installerLog',dict(state='observed',reason='arbitrary',selection=None))):
                wrong=copy.deepcopy(receipt);wrong['originalCalls'][index][key]=value
                with self.subTest(key=key),self.assertRaises(A.M.Refused):check(wrong)
            wrong=copy.deepcopy(receipt);wrong['originalCalls'][0]['installerLog']=None
            with self.assertRaises(A.M.Refused):check(wrong)


class CandidateWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text=(ROOT/'.github/workflows/desktop-macos-installed.yml').read_text()
        cls.workflow=json.loads(subprocess.run(['ruby','-ryaml','-rjson','-e',
            'puts JSON.generate(YAML.respond_to?(:unsafe_load_file) ? YAML.unsafe_load_file(ARGV[0]) : YAML.load_file(ARGV[0]))',str(ROOT/'.github/workflows/desktop-macos-installed.yml')],
            check=True,capture_output=True,text=True,timeout=10).stdout)

    def test_workflow_files_stay_below_github_size_limit(self):
        for name in ('desktop-macos-installed.yml','desktop-macos-candidate-tests.yml'):
            with self.subTest(name=name):
                self.assertLessEqual((ROOT/'.github/workflows'/name).stat().st_size,500*1024)

    @classmethod
    def saved_test_job(cls):
        caller=cls.workflow['jobs']['candidate-tests']
        path=ROOT/caller['uses'].removeprefix('./')
        workflow=json.loads(subprocess.run(['ruby','-ryaml','-rjson','-e',
            'puts JSON.generate(YAML.respond_to?(:unsafe_load_file) ? YAML.unsafe_load_file(ARGV[0]) : YAML.load_file(ARGV[0]))',
            str(path)],check=True,capture_output=True,text=True,timeout=10).stdout)
        return workflow['jobs']['candidate-tests']

    def test_successful_build_exports_before_any_install_or_ui_test(self):
        job=self.workflow['jobs']['engineering-install'];steps=job['steps']
        ids={row.get('id'):row for row in steps if row.get('id')}
        self.assertIn("'tool-setup'",ids['prepared_export']['if'])
        self.assertIn("'git-native'",ids['prepared_export']['if'])
        self.assertNotIn("'tool-setup'",ids['package_install']['if'])
        self.assertNotIn("'git-native'",ids['package_install']['if'])
        for old in ('git_native','tool_service','installed_cli_native','tool_inputs','tool_native','upload_key_native'):
            self.assertNotIn(old,ids)
        for key in ('prepared_upload_first','prepared_upload_retry'):
            self.assertIs(ids[key]['with']['overwrite'],False)
            self.assertEqual(ids[key]['with']['retention-days'],14)
            self.assertIn('github.run_attempt',ids[key]['with']['name'])

    def test_every_group_is_an_independent_fresh_runner_and_has_no_app_build_or_notary(self):
        job=self.saved_test_job()
        self.assertEqual(self.workflow['jobs']['candidate-tests']['needs'],'engineering-install')
        self.assertIs(job['strategy']['fail-fast'],False)
        expression=job['strategy']['matrix']['include']
        literals=re.findall(r"fromJSON\('([^']+)'\)",expression)
        self.assertEqual(len(literals),2)
        singles,initial=map(json.loads,literals)
        self.assertEqual(set(singles),{'git-local','git-fetch','git-push','git-create','git-upstream',
            'service-cli','public-acquisition','sdk-registration','upload-keys','cold-restart','backup'})
        self.assertEqual(initial,[singles['git-local'][0]])
        # Service lifecycle is qualified separately on the owner's Mac, where
        # its actual administrator approval can be given. The saved singleton
        # remains available; skipping it here never records a service success.
        self.assertTrue(all(len(rows)==1 and rows[0]['group']==name for name,rows in singles.items()))
        rows=[r[0] for r in singles.values()]
        steps=job['steps'];commands='\n'.join(r.get('run','') for r in steps)
        self.assertIn('mktemp -d',commands)
        self.assertIn('filter=all&per_page=100',commands)
        self.assertIn('attempts/$PRODUCER_ATTEMPT',commands)
        self.assertIn('macos_prepared_package.py hydrate',commands)
        self.assertIn('macos_prepared_package.py package-install',commands)
        for forbidden in ('macos_installed_app_build.sh','npm ci','notarize-payload','finalize-package','notarytool','sign-root-app'):
            self.assertNotIn(forbidden,commands)
        download=next(r for r in steps if r.get('uses','').startswith('actions/download-artifact'))
        self.assertEqual(download['with']['digest-mismatch'],'error')
        self.assertIn('artifact-id',download['with']['artifact-ids'])
        self.assertEqual(job['env']['MRK_MACOS_PREPARED_TEST'],'true')
        for row in rows:self.assertEqual(row['runner'],P.NATIVE_HOSTS[row['native_scope']])

    def test_dispatch_uses_selected_origin_and_checks_credentials_before_download(self):
        job=self.saved_test_job();steps=job['steps']
        credential=next(i for i,r in enumerate(steps) if r['name'].startswith('Check signing credential availability'))
        download=next(i for i,r in enumerate(steps) if r.get('uses','').startswith('actions/download-artifact'))
        self.assertLess(credential,download)
        self.assertEqual(self.workflow['jobs']['candidate-tests']['secrets'],'inherit')
        self.assertIn('prepared_run',steps[download]['with']['run-id'])
        commands='\n'.join(r.get('run','') for r in steps)
        self.assertIn('compare/$PRODUCER_SOURCE...$GITHUB_SHA',commands)
        old=next(r for r in steps if r['name'].startswith('Check out the immutable producer source'))
        self.assertEqual(old['with']['path'],'prepared-built-source')
        self.assertIn('inputs.test_group',self.workflow['concurrency']['group'])
        self.assertIs(self.workflow['concurrency']['cancel-in-progress'],False)

    def test_actual_dispatch_capture_accepts_same_source_and_fetches_only_needed_comparison(self):
        job = self.saved_test_job()
        script = next(s['run'] for s in job['steps']
                      if s['name'].startswith('Capture the exact selected producer attempt'))
        stub = '''gh() {
  [[ "$1" == api && $# == 2 ]] || return 90
  case "$2" in
    "repos/$GITHUB_REPOSITORY/actions/runs/41/attempts/1") printf '%s\\n' '{"inertRun":true}' ;;
    "repos/$GITHUB_REPOSITORY/compare/$PRODUCER_SOURCE...$GITHUB_SHA") printf '%s\\n' '{"inertComparison":true}' ;;
    *) return 91 ;;
  esac
}
'''
        for source, current, success, comparison in (
            ('1' * 40, '1' * 40, True, False),
            ('1' * 40, '6' * 40, True, True),
            ('invalid', '6' * 40, False, False),
        ):
            with self.subTest(source=source, current=current), tempfile.TemporaryDirectory() as directory:
                work = Path(directory); (work / 'prepared-service').mkdir()
                env = dict(PATH='/usr/bin:/bin', GITHUB_REPOSITORY=P.REPOSITORY,
                    PRODUCER_RUN='41', PRODUCER_ATTEMPT='1', PRODUCER_SOURCE=source,
                    GITHUB_SHA=current, MRK_MACOS_PREPARED_RESUME='true', MRK_MACOS_WORK=str(work))
                result = subprocess.run(['/bin/bash', '-c', stub + script], env=env,
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode == 0, success, result.stderr)
                self.assertEqual((work / 'prepared-service/compatibility.json').exists(), comparison)
                status = work / 'prepared-service/metadata.status'
                self.assertEqual(status.exists(), success)
                if success:
                    self.assertEqual(status.read_bytes(), b'0\n')

    def test_no_publication_or_production_branch_and_no_signing_credentials_in_artifacts(self):
        job=self.saved_test_job()
        self.assertIn('refs/heads/verify/desktop-macos-candidate',job['if'])
        for step in job['steps']:
            script=step.get('run','')
            self.assertNotIn('gh release',script)
            self.assertNotIn('git push',script)
            if step.get('uses','').startswith('actions/upload-artifact'):
                paths=step['with']['path'].splitlines()
                self.assertEqual(len(paths),8)
                self.assertTrue(all('/android-helper-' in p and p.endswith(('.stderr','.stdout','.status')) for p in paths))


if __name__=='__main__': unittest.main()
