"""Verify the actual job graph preserves completed builds on a failed-job rerun."""
import json
from pathlib import Path
import subprocess
import unittest

from desktop.tools import macos_candidate_parts as P

ROOT = Path(__file__).resolve().parents[2]


def yaml(path):
    result = subprocess.run(['ruby','-ryaml','-rjson','-e',
        'puts JSON.generate(YAML.safe_load(File.read(ARGV[0]), aliases: true))',str(ROOT/path)],
        check=True,capture_output=True,timeout=10)
    return json.loads(result.stdout)


class CandidatePartsWorkflowTests(unittest.TestCase):
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
