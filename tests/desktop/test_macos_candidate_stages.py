"""Checkpoint/rerun correspondence. All packages and native ports are inert."""
import copy
import json
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.desktop.test_macos_prepared_package import P, fixture
from tests.desktop import test_macos_identity_current_runtime as D
from tests.desktop import test_macos_aqua_qualification as A

ROOT = Path(__file__).resolve().parents[2]


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


class CandidateWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text=(ROOT/'.github/workflows/desktop-macos-installed.yml').read_text()
        cls.workflow=json.loads(subprocess.run(['ruby','-ryaml','-rjson','-e',
            'puts JSON.generate(YAML.respond_to?(:unsafe_load_file) ? YAML.unsafe_load_file(ARGV[0]) : YAML.load_file(ARGV[0]))',str(ROOT/'.github/workflows/desktop-macos-installed.yml')],
            check=True,capture_output=True,text=True,timeout=10).stdout)

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
        job=self.workflow['jobs']['candidate-tests']
        self.assertEqual(job['needs'],'engineering-install')
        self.assertIs(job['strategy']['fail-fast'],False)
        rows=job['strategy']['matrix']['include']
        self.assertEqual({r['group'] for r in rows},{'git-local','git-fetch','git-push','git-create','git-upstream',
            'service-cli','public-acquisition','sdk-registration','upload-keys','cold-restart','backup'})
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

    def test_no_publication_or_production_branch_and_no_signing_credentials_in_artifacts(self):
        job=self.workflow['jobs']['candidate-tests']
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
