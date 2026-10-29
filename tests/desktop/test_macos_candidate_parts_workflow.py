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
    def test_actual_jobs_preserve_each_original_cut_and_only_the_failed_part_retries(self):
        workflow = yaml(P.WORKFLOW); jobs = workflow['jobs']
        for scope,(profile,runner) in P.PROFILES.items():
            prefix = 'candidate-' + profile.lower()
            cuts = []
            for part in P.PARTS:
                job = jobs[prefix + '-' + part]
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
