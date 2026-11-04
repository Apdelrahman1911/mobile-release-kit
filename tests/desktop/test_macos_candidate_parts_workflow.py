"""Verify the actual job graph preserves completed builds on a failed-job rerun."""
import json
from pathlib import Path
import re
import subprocess
import tomllib
import unittest
import os
import tempfile
import shutil

from desktop.tools import macos_candidate_parts as P

ROOT = Path(__file__).resolve().parents[2]


def yaml(path):
    result = subprocess.run(['ruby','-ryaml','-rjson','-e',
        'puts JSON.generate(YAML.safe_load(File.read(ARGV[0]), aliases: true))',str(ROOT/path)],
        check=True,capture_output=True,timeout=10)
    return json.loads(result.stdout)


class CandidatePartsWorkflowTests(unittest.TestCase):
    def test_original_maintenance_storage_and_recovery_arithmetic(self):
        rustc = shutil.which('rustc')
        self.assertIsNotNone(rustc, 'the existing Rust compiler is required; download nothing')
        transaction = (ROOT/'desktop/src-tauri/src/macos_install_transaction.rs').read_text()
        installer = (ROOT/'desktop/src-tauri/src/bin/macos_install.rs').read_text()
        fixture = (ROOT/'tests/desktop/fixtures/maintenance_storage_data.rs').read_text()

        def insert(marker, value):
            nonlocal fixture
            token = '/* '+marker+' */'
            self.assertEqual(fixture.count(token), 1)
            fixture = fixture.replace(token, value)

        def declaration(source, name):
            return re.search(r'(?m)^pub const '+name+r':[^;]+;', source).group(0)

        def function(source, name):
            first = source.index('fn '+name+'(')
            opening = source.index('{', first)
            depth = 1
            last = opening+1
            while depth:
                depth += (source[last] == '{') - (source[last] == '}')
                last += 1
            return source[first:last]

        constants = []
        for path, names in (
            ('macos_install_record.rs', ('CONTROL_LIMIT','FILE_LIMIT','ORIGINAL_LIMIT','PAYLOAD_LIMIT')),
            ('macos_install_maintenance.rs', ('PREDECESSOR_LIMIT',)),
            ('macos_install_transaction.rs', ('INTENT_LIMIT','STATE_LIMIT','CAPSULE_LIMIT',
                                              'REQUEST_EXPORT_LIMIT','INVOCATION_LIMIT','PRODUCER_CONTROL_LIMIT',
                                              'MAINTENANCE_STORAGE_LIMIT')),
        ):
            source = (ROOT/'desktop/src-tauri/src'/path).read_text()
            constants += [declaration(source, name) for name in names]
        producer = (ROOT/'desktop/src-tauri/src/macos_install_producer.rs').read_text()
        constants += ['mod macos_install_producer { '+declaration(producer,'DESCRIPTOR_LIMIT')
                      +declaration(producer,'SIGNATURE_LIMIT')+' }']
        error = transaction[transaction.index('pub enum TransactionDataError '):transaction.index('fn hex(')]
        insert('MRK_ORIGINAL_BUDGET_CONSTANTS', '\n'.join(constants)+
               '\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n'+error)
        first = transaction.index('#[derive(Clone, Copy, Debug)]\npub struct GenerationCostData')
        last = transaction.index('#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub enum StepData', first)
        insert('MRK_ORIGINAL_BUDGET_TYPES_AND_METHODS',function(transaction,'maintenance_storage_sum_data')+
               '\n'+transaction[first:last])
        insert('MRK_ORIGINAL_EXISTING_BUDGET_REGRESSION',function(transaction,
               'retained_storage_and_original_budget_arithmetic_refuse_before_effects'))
        insert('MRK_ORIGINAL_UPDATE_BUDGET_REGRESSION',function(transaction,
               'update_storage_and_first_refusal_preserve_individual_limits'))
        removal_record = (ROOT/'desktop/src-tauri/src/macos_remove_record.rs').read_text()
        insert('MRK_ORIGINAL_REMOVAL_RECORD_LIMIT',declaration(removal_record,'RECORD_LIMIT'))
        insert('MRK_ORIGINAL_LINKED_WORK_LIMIT',re.search(r'const REMOVAL_LINKED_WORK:[^;]+;',installer).group(0))
        for marker, name in (
            ('MRK_ORIGINAL_ARCHIVE_STORAGE_SUM','removal_archive_storage_sum_data'),
            ('MRK_ORIGINAL_REMOVAL_PAYLOAD_ALLOCATION','removal_payload_allocation_data'),
            ('MRK_ORIGINAL_REMOVAL_LINKED_QUOTE','removal_linked_quote_data'),
        ):
            insert(marker, function(installer, name))
        with tempfile.TemporaryDirectory(dir=os.environ.get('MRK_PART_TEST_ROOT')) as temporary:
            source=Path(temporary)/'original-data.rs'; binary=Path(temporary)/'original-data'
            source.write_text(fixture)
            subprocess.run([rustc,'--edition=2021',str(source),'-o',str(binary)],
                           check=True,capture_output=True,timeout=30)
            result=subprocess.run([str(binary)],check=True,capture_output=True,timeout=5)
        self.assertEqual(result.stdout,b'MRK_MAINTENANCE_STORAGE_DATA=PASS\n')
        self.assertEqual(result.stderr,b'')

    def test_existing_app_macl_original_reader_with_inert_filesystem_returns(self):
        native=(ROOT/'desktop/native/macos-installed-native/src/native.m').read_text()
        start=native.index('int mrk_no_xattrs(')
        end=native.index('\n#ifndef MRK_ENTRY_METADATA_ONLY',start)
        fixture=(ROOT/'tests/desktop/fixtures/existing_app_macl_data.c').read_text()
        self.assertEqual(fixture.count('/* MRK_EXISTING_APP_MACL_ORIGINAL */'),1)
        body=fixture.replace('/* MRK_EXISTING_APP_MACL_ORIGINAL */',native[start:end])
        with tempfile.TemporaryDirectory(dir=os.environ.get('MRK_PART_TEST_ROOT')) as temporary:
            source=Path(temporary)/'original-data.c'; binary=Path(temporary)/'original-data'
            source.write_text(body)
            subprocess.run(['/usr/bin/clang','-x','c','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],
                           check=True,capture_output=True,timeout=30)
            result=subprocess.run([str(binary)],check=True,capture_output=True,timeout=5)
        self.assertEqual(result.stdout,b'MRK_EXISTING_APP_MACL_DATA=29\n')
        self.assertEqual(result.stderr,b'')

    def test_existing_app_metadata_callbacks_and_original_conservation_are_connected(self):
        source=(ROOT/'desktop/src-tauri/src/macos_existing_app_metadata.rs').read_text()
        observer=(ROOT/'desktop/src-tauri/src/installed_shell_observation_macos.rs').read_text()
        for name in ('assert_existing_app_metadata_bounds','assert_existing_app_metadata_conservation'):
            self.assertRegex(source,r'pub fn '+name+r'\(')
            self.assertIn('crate::macos_existing_app_metadata::'+name+'();',observer)
        installer=(ROOT/'desktop/src-tauri/src/bin/macos_install.rs').read_text()
        audit=installer[installer.index('fn audit_generation_mode('):installer.index('// Strict known-control prelude')]
        self.assertLess(audit.index('"maintenance-app-original"'),audit.index('book.capture_existing_app_metadata('))
        capture=installer[installer.index('fn capture_existing_app_metadata('):installer.index('fn app_attributes(')]
        self.assertLess(capture.index('SnapshotData::conserve_data('),capture.index('existing_app_metadata=Some(captured)'))
        self.assertIn('let existing=allow_existing_macl && !self.creations.iter()',capture)
        self.assertIn('if !existing {native::no_xattrs(',capture)
        self.assertIn('None,false,inverse || observed.action==ActionData::SamePackageNoop',installer)
        self.assertIn('if prefix=="app" && depth==0',installer)
        self.assertIn('book.app_attributes(original,"maintenance-renamed-attributes")',installer)
        self.assertRegex(installer,r'if !metadata_ok\s*\{\s*self\.unknown=true;\s*\}')
        self.assertNotIn('setxattr',source)

    def test_existing_launcher_metadata_original_control_flow(self):
        rustc = shutil.which('rustc')
        self.assertIsNotNone(rustc, 'the existing Rust compiler is required; download nothing')
        installer=(ROOT/'desktop/src-tauri/src/bin/macos_install.rs').read_text()
        body=(ROOT/'tests/desktop/fixtures/existing_launcher_metadata_data.rs').read_text()
        for marker,start,end in (
            ('MRK_EXISTING_METADATA_POST_ORIGINAL','fn existing_app_metadata_post(','// Call only after'),
            ('MRK_EXISTING_METADATA_CAPTURE_ORIGINAL','fn capture_existing_app_metadata(','fn app_attributes('),
            ('MRK_APP_ATTRIBUTES_ORIGINAL','fn app_attributes(','fn protected('),
        ):
            first=installer.index(start); last=installer.index(end,first)
            token='/* '+marker+' */'; self.assertEqual(body.count(token),1)
            body=body.replace(token,installer[first:last])
        first=installer.index('if prefix=="app" && depth==0')
        last=installer.index('check(stat::fstat(',first)
        token='/* MRK_TREE_ROOT_ATTRIBUTES_ORIGINAL */'; self.assertEqual(body.count(token),1)
        body=body.replace(token,installer[first:last])
        with tempfile.TemporaryDirectory(dir=os.environ.get('MRK_PART_TEST_ROOT')) as temporary:
            source=Path(temporary)/'original-data.rs'; binary=Path(temporary)/'original-data'
            source.write_text(body)
            subprocess.run([rustc,'--edition=2021',str(source),'-o',str(binary)],
                           check=True,capture_output=True,timeout=30)
            result=subprocess.run([str(binary)],check=True,capture_output=True,timeout=5)
        self.assertEqual(result.stdout,b'MRK_EXISTING_LAUNCHER_METADATA_DATA=PASS\n')
        self.assertEqual(result.stderr,b'')

    def test_launcher_existing_metadata_requires_original_enrollment(self):
        launcher=(ROOT/'desktop/src-tauri/src/macos_applications_native.rs').read_text()
        hold=launcher[launcher.index('pub(super) fn hold_matching('):launcher.index('pub(super) fn stage(')]
        self.assertLess(hold.index('require_enrolled('),hold.index('capture_existing_app_metadata('))
        self.assertLess(hold.index('capture_existing_app_metadata('),hold.index('audit_launcher_tree('))
        self.assertIn('current.hold_matching(book,&self.current.index(),row.published_identity,false)',launcher)
        retirement=launcher[launcher.index('fn capture_remaining('):launcher.index('fn unlink(')]
        self.assertIn('if let Some(enrolled)=enrolled {\n            require_enrolled(',retirement)
        self.assertIn('if path.is_empty() {book.app_attributes(',retirement)
        self.assertIn('if slot==0 && directory {book.app_attributes(',launcher)

    def test_observer_callback_dependencies_are_declared_in_its_actual_crate(self):
        manifest = tomllib.loads((ROOT/'desktop/src-tauri/Cargo.toml').read_text())
        target = next(row for row in manifest['test']
                      if row['name'] == 'installed-shell-observation')
        root_path = ROOT/'desktop/src-tauri'/target['path']
        root = root_path.read_text()
        observer = (ROOT/'desktop/src-tauri/src/installed_shell_observation_macos.rs').read_text()
        declared = set(re.findall(r'\bmod\s+([A-Za-z_]\w*)\s*;', root))
        referenced = set(re.findall(r'\bcrate::([A-Za-z_]\w*)::', observer))
        self.assertTrue(referenced)
        self.assertEqual(referenced - declared, set(),
                         'observer callbacks need modules in the custom test crate, independently of lib.rs')
        metadata = re.findall(
            r'#\[path\s*=\s*"([^"]+)"\]\s*mod\s+macos_existing_app_metadata\s*;', root)
        self.assertEqual(len(metadata), 1)
        self.assertEqual((root_path.parent/metadata[0]).resolve(),
                         (ROOT/'desktop/src-tauri/src/macos_existing_app_metadata.rs').resolve())

    def test_custom_observer_data_callbacks_are_available_without_libtest(self):
        manifest = tomllib.loads((ROOT/'desktop/src-tauri/Cargo.toml').read_text())
        observer = next(row for row in manifest['test']
                        if row['name'] == 'installed-shell-observation')
        self.assertFalse(observer['harness'])
        source = (ROOT/'desktop/src-tauri/src/macos_install_record.rs').read_text()
        callback = re.search(
            r'pub\(crate\) fn assert_installation_record_data_contract\(\)\s*\{([^}]+)\}',
            source)
        self.assertIsNotNone(callback)
        calls = set(re.findall(r'\btests::([A-Za-z_]\w*)\s*\(', callback.group(1)))
        self.assertTrue(calls)
        declarations = list(re.finditer(
            r'(?m)^[ \t]*(?P<inline>(?:#\[[^\n]+?\][ \t]*)*)'
            r'(?:pub(?:\([^)]*\))?[ \t]+)?fn[ \t]+(?P<name>[A-Za-z_]\w*)\s*\(',
            source))
        for name in calls:
            matches = [row for row in declarations if row.group('name') == name]
            self.assertEqual(len(matches), 1, name)
            declaration = matches[0]
            attributes = [declaration.group('inline')]
            for line in reversed(source[:declaration.start()].splitlines()):
                stripped = line.strip()
                if not stripped or stripped.startswith('//'):
                    continue
                if re.fullmatch(r'#\[[^\n]+\]', stripped):
                    attributes.append(stripped)
                    continue
                break
            self.assertFalse(any(re.search(r'#\[\s*test\s*\]', row)
                                 for row in attributes),
                             f'{name} is only available to the Rust test runner')

    def test_workflow_fits_github_limit_and_shared_recipe_bindings_are_complete(self):
        self.assertLess((ROOT/P.WORKFLOW).stat().st_size,500000)
        jobs=yaml(P.WORKFLOW)['jobs']
        checked=set()
        for job in jobs.values():
            checkout=False
            for step in job.get('steps',[]):
                route=step.get('uses','')
                if route.startswith('actions/checkout@'):
                    checkout=True
                if route.startswith('./'):
                    self.assertTrue(checkout,'source-owned actions require the exact checkout first')
                if not route.startswith('./.github/actions/macos-candidate-recipes/'):
                    continue
                action=yaml(route[2:]+'/action.yml')
                self.assertEqual(action['runs']['using'],'composite')
                self.assertEqual(len(action['runs']['steps']),1)
                recipe=action['runs']['steps'][0]
                self.assertEqual(recipe['id'],'recipe')
                self.assertNotIn('timeout-minutes',recipe)
                self.assertEqual(set(step.get('with',{})),set(action.get('inputs',{})))
                for name,definition in action.get('inputs',{}).items():
                    self.assertTrue(definition['required'])
                    self.assertIn('${{ inputs.'+name+' }}',recipe['run'])
                    self.assertTrue(step['with'][name].startswith('${{ '))
                self.assertNotIn('${{ steps.',recipe['run'])
                for name,definition in action.get('outputs',{}).items():
                    self.assertEqual(definition['value'],'${{ steps.recipe.outputs.'+name+' }}')
                checked.add(route)
        self.assertGreater(len(checked),0)

    def test_actual_jobs_preserve_each_original_cut_and_only_the_failed_part_retries(self):
        workflow = yaml(P.WORKFLOW); jobs = workflow['jobs']
        data_command=jobs['candidate-parts-data']['steps'][-1]['run']
        self.assertIn('tests.desktop.test_macos_candidate_stages',data_command.split())
        self.assertIn('tests.desktop.test_macos_optional_arrays',data_command.split())
        self.assertNotIn('test_macos_candidate_stages.FixedSigningFailureDiagnosticTests',data_command)
        for scope,(profile,runner) in P.PROFILES.items():
            prefix = 'candidate-' + profile.lower()
            cuts = []
            for part in P.PARTS:
                job = jobs[prefix + '-' + part]
                self.assertIn('matrix.native_scope',job['name'])
                self.assertEqual(job['strategy']['matrix']['include'][0]['native_scope'],scope)
                self.assertEqual(job['strategy']['matrix']['include'][0]['runner'],runner)
                self.assertFalse(job['strategy']['fail-fast'])
                expected = [prefix + '-' + name for name in P.ancestors(part)] if part != 'prepare' else ['candidate-parts-data']
                self.assertEqual(job['needs'],expected)
                names = [step['name'] for step in job['steps']]
                for name in P.ORIGINAL_CUTS[part]:
                    self.assertEqual(names.count(name),1);cuts.append(name)
                if part != 'final-package':
                    self.assertIn('Verify and freeze completed part originals',names)
                    upload = next(s for s in job['steps'] if s['name']=='Upload immutable completed part')
                    self.assertEqual(upload['with']['overwrite'],False)
                    self.assertEqual(upload['with']['retention-days'],14)
                if part in ('sign-remover','sign-cli'):
                    self.assertNotIn('Build the current nonshipping observer',names)
                    self.assertFalse(any('macos_installed_app_build.sh' in s.get('run','') for s in job['steps']))
                if part=='prepare':
                    self.assertIn('run',job['steps'][0])
                    self.assertEqual(job['steps'][0]['name'],'Admit only this exact disposable-hosted source route')
                    self.assertTrue(job['steps'][1]['uses'].startswith('actions/checkout@'))
            self.assertEqual(len(cuts),17);self.assertEqual(len(set(cuts)),17)
        auto=jobs['candidate-tests']
        self.assertEqual(auto['needs'],['engineering-install','candidate-tool26-final-package','candidate-git27-final-package'])
        self.assertIn("needs.candidate-tool26-final-package.result == 'success'",auto['if'])
        self.assertIn("needs.candidate-git27-final-package.result == 'success'",auto['if'])
        self.assertNotIn("github.ref == 'refs/heads/verify/desktop-macos-candidate'",jobs['engineering-install']['if'])

    def test_actual_source_actions_use_fresh_admission_without_reusing_old_work_identity(self):
        bootstrap=yaml('.github/actions/macos-candidate-bootstrap/action.yml')
        work=next(s for s in bootstrap['runs']['steps'] if s.get('id')=='work')
        self.assertIn('! -e "$root" && ! -L "$root"',work['run'])
        self.assertIn('work_info = os.stat',work['run'])
        self.assertIn('os.environ["GITHUB_RUN_ATTEMPT"]',work['run'])
        bindings=yaml('.github/actions/macos-candidate-bindings/action.yml')
        self.assertIn('finalize-runtime-binding',bindings['runs']['steps'][0]['run'])
        for action in (bootstrap,bindings):
            self.assertEqual(action['runs']['using'],'composite')
            for step in action['runs']['steps']:
                self.assertNotIn('timeout-minutes',step)
                if 'uses' in step and not step['uses'].startswith('./'):
                    self.assertRegex(step['uses'],r'@[0-9a-f]{40}$')


if __name__=='__main__':unittest.main()
