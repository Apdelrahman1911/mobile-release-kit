"""Run the real cohort shell with an inert child, never native/Store work."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]


class EntryWorkflowTests(unittest.TestCase):
    def test_selected_cohort_order_and_failure_stop(self):
        source = (ROOT / '.github/workflows/desktop-macos-candidate-consume.yml').read_text()
        block = source.split('        id: ordinary_ui\n', 1)[1].split('\n      - name:', 1)[0]
        script = textwrap.dedent(block.split('        run: |\n', 1)[1])
        ordinary = ('build', 'applications-test', 'applications-summary', 'project-test',
                    'project-summary', 'persistence-test', 'persistence-summary',
                    'saved-checks-test', 'saved-checks-summary', 'result', 'cleanup')
        entry = ('build', 'test', 'summary', 'result', 'cleanup')
        for mode, phases in (('ordinary-ui', ordinary), ('ordinary-entry-ui', entry)):
            for failure in ('none', 'child', 'status', 'child-and-status'):
                with self.subTest(mode=mode, failure=failure), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    work = root / 'work'
                    workspace = root / 'workspace'
                    tools = workspace / '.candidate-consumer-helper/desktop/tools'
                    tools.mkdir(parents=True)
                    (work / 'host-python/bin').mkdir(parents=True)
                    (work / 'normal-ui').mkdir()
                    (work / 'host-python/bin/python3').symlink_to(sys.executable)
                    # Source is fixed locally; no runner payload or production import.
                    (tools / 'macos_candidate_ui.py').write_text(textwrap.dedent(f'''
                        import json, os, pathlib, sys
                        assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
                        assert 'GH_TOKEN' not in os.environ and 'GITHUB_TOKEN' not in os.environ
                        assert sys.argv[1:-1] == {(['--entry'] if mode.endswith('entry-ui') else [])!r}
                        phase = sys.argv[-1]
                        work = pathlib.Path(os.environ['MRK_MACOS_WORK'])
                        with (work / 'calls.jsonl').open('a') as output:
                            output.write(json.dumps(phase) + '\\n')
                        if phase == {phases[1]!r}:
                            if {failure!r} in ('status', 'child-and-status'):
                                (work / 'normal-ui' / (phase + '.status')).mkdir()
                            if {failure!r} in ('child', 'child-and-status'):
                                sys.exit(23)
                        print('{{}}')
                    '''))
                    env = dict(PATH='/usr/bin:/bin', MRK_MACOS_WORK=str(work),
                               GITHUB_WORKSPACE=str(workspace), MRK_CANDIDATE_MODE=mode,
                               GITHUB_TOKEN='inert-must-not-reach-child', GH_TOKEN='inert')
                    result = subprocess.run(['/bin/bash', '-c', script], env=env,
                                            capture_output=True, timeout=15)
                    calls = [json.loads(line) for line in (work / 'calls.jsonl').read_text().splitlines()]
                    self.assertEqual(calls, list(phases if failure == 'none' else phases[:2]))
                    self.assertEqual(result.returncode, 0 if failure == 'none' else
                                     23 if failure in ('child', 'child-and-status') else 1)
                    for phase in calls:
                        status = (work / ('candidate-ui-' + phase + '.status') if phase in ('result', 'cleanup')
                                  else work / 'normal-ui' / (phase + '.status'))
                        if status.is_file():
                            expected = '23\n' if failure == 'child' and phase == phases[1] else '0\n'
                            self.assertEqual(status.read_text(), expected)
        # Invalid cohort must stop before invoking any child.
        result = subprocess.run(['/bin/bash', '-c', script], env=dict(PATH='/usr/bin:/bin',
                                MRK_CANDIDATE_MODE='unrecognized'), capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)


if __name__ == '__main__':
    unittest.main()
